/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <stdio.h>
#include <string.h>
#include "cryptoki.h"
#include "pkcs11_debug.h"
#include "pkcs11_init.h"
#include "pkcs11_session.h"
#include "pkcs11_object.h"

/**
 * \defgroup pkcs11 Object (pkcs11_object_)
   @{ */

static CK_BYTE pkcs11_find_template_cache[PKCS11_SEARCH_CACHE_SIZE];

/**
 * \brief Check if the library is initialized properly
 */
CK_RV qti_pkcs11_init_check(pkcs11_lib_ctx_ptr * ppContext, CK_BBOOL lock)
{
    pkcs11_lib_ctx_ptr lib_ctx = qti_pkcs11_get_context();

    if (lib_ctx && lib_ctx->initialized)
        return CKR_OK;
    else
        return CKR_CRYPTOKI_NOT_INITIALIZED;
}

/**
 * \brief Copy an array of CK_ATTRIBUTE structures
 */
static CK_RV qti_pkcs11_find_copy_template(CK_BYTE_PTR pBuffer, CK_ULONG ulBufSize, CK_ATTRIBUTE_PTR pTemplate, const CK_ULONG ulCount)
{
    CK_ULONG bytes_required;
    CK_ATTRIBUTE_PTR pCopy;
    CK_ULONG i;

    if (!pBuffer || !ulBufSize || !pTemplate || !ulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Start with the amount of memory required to hold the Array */
    bytes_required = sizeof(CK_ATTRIBUTE) * ulCount;

    /* Check the template pValue requirements */
    for (i = 0; i < ulCount; i++)
    {
        if (pTemplate[i].pValue && pTemplate[i].ulValueLen)
        {
            bytes_required += pTemplate[i].ulValueLen;

            /* Check for overflow */
            if (bytes_required < pTemplate[i].ulValueLen)
            {
                return CKR_HOST_MEMORY;
            }
        }
    }

    if (ulBufSize < bytes_required)
    {
        return CKR_HOST_MEMORY;
    }

    /* Good to copy */
    bytes_required = sizeof(CK_ATTRIBUTE) * ulCount;

    /* Set up the Copied Template */
    pCopy = (CK_ATTRIBUTE_PTR)pBuffer;

    /* Move to the data section */
    pBuffer += bytes_required;

    /* Copy the template */
    for (i = 0; i < ulCount; i++)
    {
        pCopy[i].type = pTemplate[i].type;

        /* Sanity check the input to see if we need to allocate any memory for this */
        if (pTemplate[i].pValue && pTemplate[i].ulValueLen)
        {
            pCopy[i].pValue = pBuffer;
            pCopy[i].ulValueLen = pTemplate[i].ulValueLen;
            pBuffer += pTemplate[i].ulValueLen;
            memcpy(pCopy[i].pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
        }
        else
        {
            pCopy[i].pValue = NULL_PTR;
            pCopy[i].ulValueLen = 0;
        }
    }

    return CKR_OK;
}

static pkcs11_attrib_model_ptr qti_pkcs11_find_attrib(const pkcs11_attrib_model_ptr pAttributeList, const CK_ULONG ulCount, const CK_ATTRIBUTE_PTR pTemplate)
{
    CK_ULONG i;
    pkcs11_attrib_model_ptr pAttribute = NULL_PTR;

    if (pAttributeList && ulCount && pTemplate)
    {
        for (i = 0; i < ulCount; i++)
        {
            pAttribute = &pAttributeList[i];
            if (pAttribute->type == pTemplate->type)
            {
                return pAttribute;
            }
        }
    }

    return NULL_PTR;
}

static pkcs11_attrib_model_ptr qti_pkcs11_find_attrib_match(pkcs11_object_ptr pObject, const pkcs11_attrib_model_ptr pAttributeList, const CK_ULONG ulCount, const CK_ATTRIBUTE_PTR pTemplate)
{
    CK_BBOOL found = FALSE;
    pkcs11_attrib_model_ptr pAttribute = NULL_PTR;

    pAttribute = qti_pkcs11_find_attrib(pAttributeList, ulCount, pTemplate);

    if (pAttribute && pObject)
    {
        CK_BBOOL must_full_match = FALSE;

        /* Special rules - only return CKO_HW_FEATURE (Sec 4.3.2) or CKO_MECHANISM (Sec 4.12.2) if the search attributes contain them */
        if (CKA_CLASS == pAttribute->type)
        {
            if ((CKO_HW_FEATURE == pObject->class_id) || (CKO_MECHANISM == pObject->class_id))
            {
                must_full_match = TRUE;
            }
        }

        /* Search criteria has a value to we must match it */
        if (pTemplate->pValue && pAttribute->func)
        {
            CK_UTF8CHAR buf[PKCS11_MAX_LABEL_SIZE];
            CK_ATTRIBUTE temp = { 0, buf, sizeof(buf) };

            /* Get the attribute */
            if (!pAttribute->func(pObject, &temp))
            {
                if ((temp.ulValueLen == pTemplate->ulValueLen))
                {
                    if (!memcmp(temp.pValue, pTemplate->pValue, pTemplate->ulValueLen))
                    {
                        found = TRUE;
                    }
                }
            }
        }
        else if (!must_full_match)
        {
            found = TRUE;
        }
    }

    if (found)
    {
        return pAttribute;
    }

    return NULL_PTR;
}

static CK_OBJECT_HANDLE qti_pkcs11_find_handle(const CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG_PTR index)
{
    CK_ULONG i;
    CK_ULONG j;
    CK_OBJECT_HANDLE rv = NULL_PTR;

    /* Finds the first or next match - Iterate through objects */
    for (i = (index) ? *index : 0; i < PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        pkcs11_object_ptr pObject = pkcs11_object_cache[i].object;
        if (pObject)
        {
            /* Iterate through attribute list */
            for (j = 0; j < ulCount; j++)
            {
                /* See if a match failed */
                if (!qti_pkcs11_find_attrib_match(pObject, (const pkcs11_attrib_model_ptr)pObject->attributes,
                                              pObject->count, &pTemplate[j]))
                {
                    break;
                }
            }
            if (j == ulCount)
            {
                /* Full match */
                if (ulCount)
                {
                    rv = pkcs11_object_cache[i].handle;
                    break;
                }
                else if ((CKO_HW_FEATURE != pObject->class_id) && (CKO_MECHANISM != pObject->class_id))
                {
                    /* Special condition where ulCount is zero we match all
                       objects except HW Features and Mechanisms */
                    rv = pkcs11_object_cache[i].handle;
                    break;
                }
            }
        }
    }

    if (index)
    {
        *index = i;
    }

    return rv;
}

CK_RV qti_pkcs11_find_init(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    pkcs11_session_ctx_ptr pSession;
    CK_ULONG index = 0;
    CK_RV rv;
    static int called;

    rv = qti_pkcs11_init_check(NULL, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pTemplate && ulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    qti_pkcs11_debug_attributes(pTemplate, ulCount);

    /* Check Public/Private Session info - although I don't think we can actually
        get private unless we're using a shared key system - and that will only be
        for secured data and not key info */

    if (qti_pkcs11_find_handle(pTemplate, ulCount, &index))
    {
        if (ulCount)
        {
            rv = qti_pkcs11_find_copy_template(pkcs11_find_template_cache, PKCS11_SEARCH_CACHE_SIZE, pTemplate, ulCount);
            if (rv)
            {
                return rv;
            }
            pSession->attrib_list = (CK_ATTRIBUTE_PTR)pkcs11_find_template_cache;
        }
        else
        {
            pSession->attrib_list = NULL_PTR;
        }
        pSession->attrib_count = ulCount;
        pSession->object_index = index;
        pSession->object_count = 1;
        index++;
        while (qti_pkcs11_find_handle(pSession->attrib_list, ulCount, &index))
        {
            pSession->object_count++;
            index++;
        }
    }

    return CKR_OK;
}

CK_RV qti_pkcs11_find_continue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    pkcs11_session_ctx_ptr pSession;
    CK_ULONG i;
    CK_RV rv;

    rv = qti_pkcs11_init_check(NULL, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!phObject || !pulObjectCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }
#if 1
    *pulObjectCount = (pSession->object_count < ulMaxObjectCount) ? pSession->object_count : ulMaxObjectCount;

    for (i = 0; i < *pulObjectCount; i++)
    {
        phObject[i] = qti_pkcs11_find_handle(pSession->attrib_list, pSession->attrib_count, &pSession->object_index);
        if (!phObject[i])
        {
            pSession->object_count = 0;
            *pulObjectCount = i;
            break;
        }

        pSession->object_index++;

        if (pSession->object_count)
        {
            pSession->object_count--;
        }
    }
#else
    /* No real object mgmt for now, return dummy */
	phObject[0] = 1; //pkcs11_object_cache[0].handle;
        *pulObjectCount = 1;
#endif

    return CKR_OK;
}

CK_RV qti_pkcs11_find_finish(CK_SESSION_HANDLE hSession)
{
    pkcs11_session_ctx_ptr pSession;
    CK_RV rv;

    rv = qti_pkcs11_init_check(NULL, FALSE);
    if (rv)
    {
        return rv;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    pSession->attrib_list = NULL_PTR;
    pSession->attrib_count = 0;
    pSession->object_count = 0;

    return CKR_OK;
}


static pkcs11_object pkcs11_object_store[PKCS11_MAX_OBJECTS_ALLOWED];
pkcs11_object_cache_t pkcs11_object_cache[PKCS11_MAX_OBJECTS_ALLOWED];

/** For object handle tracking */
static CK_OBJECT_HANDLE qti_pkcs11_object_alloc_handle(void)
{
    static CK_OBJECT_HANDLE pkcs11_object_last_handle = 1;

    if (pkcs11_object_last_handle)
    {
        pkcs11_object_last_handle++;
    }

    return pkcs11_object_last_handle;
}

CK_RV qti_pkcs11_object_alloc(pkcs11_object_ptr * ppObject)
{
    CK_ULONG i;
    CK_RV rv = CKR_OK;

    if (!ppObject)
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else
    {
        *ppObject = NULL;
    }

    for (i = 0; i < PKCS11_MAX_OBJECTS_ALLOWED && CKR_OK == rv; i++)
    {
        if (!pkcs11_object_cache[i].object)
        {
            *ppObject = &pkcs11_object_store[i];
            if (*ppObject)
            {
                memset(*ppObject, 0, sizeof(pkcs11_object));
                pkcs11_object_cache[i].handle = qti_pkcs11_object_alloc_handle();
                pkcs11_object_cache[i].object = *ppObject;
            }
            break;
        }
    }

    if (PKCS11_MAX_OBJECTS_ALLOWED == i)
    {
        rv = CKR_HOST_MEMORY;
    }

    return rv;
}

CK_RV qti_pkcs11_object_free(pkcs11_object_ptr pObject)
{
    CK_ULONG i;

    for (i = 0; i < PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (pObject == pkcs11_object_cache[i].object)
        {
            /* Delink it */
            pkcs11_object_cache[i].object = NULL_PTR;
            pkcs11_object_cache[i].handle = 0;
        }
    }

    if (pObject)
    {
        memset(pObject, 0, sizeof(pkcs11_object));
    }

    return CKR_OK;
}

CK_RV qti_pkcs11_object_check(pkcs11_object_ptr * ppObject, CK_OBJECT_HANDLE hObject)
{
    CK_ULONG i;

    if (!hObject)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    for (i = 0; i < PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (hObject == pkcs11_object_cache[i].handle)
        {
            break;
        }
    }
    if (i == PKCS11_MAX_OBJECTS_ALLOWED)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    else if (ppObject)
    {
        *ppObject = pkcs11_object_cache[i].object;
    }

    return CKR_OK;
}

CK_RV qti_pkcs11_object_get_handle(pkcs11_object_ptr pObject, CK_OBJECT_HANDLE_PTR phObject)
{
    CK_ULONG i;

    if (!phObject || !pObject)
    {
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 0; i < PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (pObject == pkcs11_object_cache[i].object)
        {
            *phObject = pkcs11_object_cache[i].handle;
            break;
        }
    }
    if (i == PKCS11_MAX_OBJECTS_ALLOWED)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    return CKR_OK;
}

CK_RV qti_pkcs11_attrib_fill(CK_ATTRIBUTE_PTR pAttribute, const CK_VOID_PTR pData, const CK_ULONG ulSize)
{
printf("%s %d\n",__func__, __LINE__);


    if (!pAttribute)
    {
        return CKR_ARGUMENTS_BAD;
    }
printf("%s %d\n",__func__, __LINE__);


    if (pAttribute->pValue)
    {
        /* 1. If the specified attribute(i.e., the attribute specified by the type field) for the object cannot be revealed
           because the object is sensitive or unextractable, then the ulValueLen field in that triple is modified to
           hold the value CK_UNAVAILABLE_INFORMATION. //if (!rv) rv = CKR_ATTRIBUTE_SENSITIVE; */
printf("%s %d\n",__func__, __LINE__);


        if (ulSize <= pAttribute->ulValueLen)
        {
            /* 4. Otherwise, if the length specified in ulValueLen is large enough to hold the value of the specified
               attribute for the object, then that attribute is copied into the buffer located at pValue */
printf("%s %d\n",__func__, __LINE__);


            if (pData)
            {
printf("%s %d\n",__func__, __LINE__);


                memcpy(pAttribute->pValue, pData, ulSize);
            }
            else
            {
                /* This case isn't covered by the PKCS11 specification as it always assumes that the internals of the
                   library should be rational about providing some data if an attribute is matched. */
printf("%s %d\n",__func__, __LINE__);
                memset(pAttribute->pValue, 0, pAttribute->ulValueLen);
            }
        }
        else
        {
            /* 5. Otherwise, the ulValueLen field is modified to hold the value CK_UNAVAILABLE_INFORMATION. */
            pAttribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
	printf("%s %d\n",__func__, __LINE__);


            return CKR_BUFFER_TOO_SMALL;
        }
    }

printf("%s %d\n",__func__, __LINE__);


    pAttribute->ulValueLen = ulSize;

    return CKR_OK;
}

/**
 * \brief Helper function to write a numerical value to an attribute buffer
 */
CK_RV qti_pkcs11_attrib_value(CK_ATTRIBUTE_PTR pAttribute, const CK_ULONG ulValue, const CK_ULONG ulSize)
{
    return qti_pkcs11_attrib_fill(pAttribute, (const CK_VOID_PTR)&ulValue, ulSize);
}

static const CK_BBOOL cbFalse = CK_FALSE;
CK_RV qti_pkcs11_attrib_false(const CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    ((void)pObject);
    return qti_pkcs11_attrib_fill(pAttribute, (const CK_VOID_PTR)&cbFalse, sizeof(cbFalse));
}

static const CK_BBOOL cbTrue = CK_TRUE;
CK_RV qti_pkcs11_attrib_true(const CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    ((void)pObject);
    return qti_pkcs11_attrib_fill(pAttribute, (const CK_VOID_PTR)&cbTrue, sizeof(cbTrue));
}

CK_RV qti_pkcs11_attrib_empty(const CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    ((void)pObject);
    return qti_pkcs11_attrib_fill(pAttribute, NULL, 0);
}

CK_RV qti_pkcs11_object_get_name(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (!obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (obj_ptr->name)
    {
        return qti_pkcs11_attrib_fill(pAttribute, (const CK_VOID_PTR)obj_ptr->name, strlen((char*)obj_ptr->name));
    }
    else
    {
        return qti_pkcs11_attrib_fill(pAttribute, NULL_PTR, 0);
    }
}

CK_RV qti_pkcs11_object_get_class(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (!obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return qti_pkcs11_attrib_fill(pAttribute, &obj_ptr->class_id, sizeof(obj_ptr->class_id));
}

CK_RV qti_pkcs11_object_get_type(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (!obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return qti_pkcs11_attrib_fill(pAttribute, &obj_ptr->class_type, sizeof(obj_ptr->class_type));
}

CK_RV qti_pkcs11_object_get_destroyable(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (!obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (obj_ptr->flags & PKCS11_OBJECT_FLAG_DESTROYABLE)
    {
        return qti_pkcs11_attrib_true(pObject, pAttribute);
    }
    else
    {
        return qti_pkcs11_attrib_false(pObject, pAttribute);
    }
}

CK_RV qti_pkcs11_object_get_size(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    pkcs11_object_ptr pObject;
    CK_RV rv;

    rv = qti_pkcs11_init_check(NULL, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pulSize)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = qti_pkcs11_session_check(NULL_PTR, hSession);
    if (rv)
    {
        return rv;
    }

    rv = qti_pkcs11_object_check(&pObject, hObject);
    if (rv)
    {
        return rv;
    }

    *pulSize = pObject->size;

    return CKR_OK;
}

CK_RV qti_pkcs11_object_find(pkcs11_object_ptr * ppObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    int i;
    CK_ATTRIBUTE_PTR pName = NULL;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;    /* Unless specified assume private key object */

    if (!ppObject || !pTemplate || !ulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Match Name and Class */
    for (i = 0; i < ulCount; i++, pTemplate++)
    {
        switch (pTemplate->type)
        {
        case CKA_LABEL:
            pName = pTemplate;
            break;
        case CKA_CLASS:
            class = *((CK_OBJECT_CLASS_PTR)pTemplate->pValue);
            break;
        default:
            break;
        }
    }

    if (pName)
    {
        for (i = 0; i < PKCS11_MAX_OBJECTS_ALLOWED; i++)
        {
            pkcs11_object_ptr pObj = pkcs11_object_cache[i].object;
            if (pObj)
            {
                if ((pObj->class_id == class) && (strlen(pObj->name) == pName->ulValueLen))
                {
                    if (!memcmp(pObj->name, pName->pValue, pName->ulValueLen))
                    {
                        *ppObject = pObj;
                        break;
                    }
                }
            }
        }
    }

    return CKR_OK;
}

const pkcs11_attrib_model pkcs11_key_private_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,               qti_pkcs11_object_get_class                                                               },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,               qti_pkcs11_attrib_true                                                                    },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,             qti_pkcs11_attrib_true                                                                    },
    /** Description of the object(default empty). */
    { CKA_LABEL,               qti_pkcs11_object_get_name                                                                },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,            qti_pkcs11_attrib_false                                                                   },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,         qti_pkcs11_object_get_destroyable                                                         },
    /** Type of key */
    { CKA_KEY_TYPE,            qti_pkcs11_object_get_type                                                                },
    /** Key identifier for key (default empty) */
    { CKA_ID,                  qti_pkcs11_attrib_empty                                                                   },
    { CKA_SIGN,                qti_pkcs11_attrib_true                                                                    },
    { CKA_VALUE,               NULL_PTR                                                                              },
};

const pkcs11_attrib_model pkcs11_key_public_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,               qti_pkcs11_object_get_class                                                               },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,               qti_pkcs11_attrib_true                                                                    },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,             qti_pkcs11_attrib_false                                                                    },
    /** Description of the object(default empty). */
    { CKA_LABEL,               qti_pkcs11_object_get_name                                                                },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,            qti_pkcs11_attrib_false                                                                   },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,         qti_pkcs11_object_get_destroyable                                                         },
    /** Type of key */
    { CKA_KEY_TYPE,            qti_pkcs11_object_get_type                                                                },
    /** Key identifier for key (default empty) */
    { CKA_ID,                  qti_pkcs11_attrib_empty                                                                   },
    { CKA_SIGN,                qti_pkcs11_attrib_true                                                                    },
    { CKA_VALUE,               NULL_PTR                                                                              },
};

const CK_ULONG pkcs11_key_private_attributes_count = sizeof(pkcs11_key_private_attributes)/sizeof(pkcs11_key_private_attributes[0]);
const CK_ULONG pkcs11_key_public_attributes_count = sizeof(pkcs11_key_public_attributes)/sizeof(pkcs11_key_public_attributes[0]);

void qti_pkcs11_config_init_private(pkcs11_object_ptr pObject, char * label, size_t len)
{
    if (len >= PKCS11_MAX_LABEL_SIZE)
    {
        len = PKCS11_MAX_LABEL_SIZE - 1;
    }
    memcpy(pObject->name, label, len);
    pObject->name[len] = '\0';
    pObject->class_id = CKO_PRIVATE_KEY;
    pObject->class_type = CKK_EC;
    pObject->attributes = pkcs11_key_private_attributes;
    pObject->count = pkcs11_key_private_attributes_count;
    pObject->data = NULL;
    pObject->size = 16;
}

void qti_pkcs11_config_init_public(pkcs11_object_ptr pObject, char * label, size_t len)
{
    if (len >= PKCS11_MAX_LABEL_SIZE)
    {
        len = PKCS11_MAX_LABEL_SIZE - 1;
    }
    memcpy(pObject->name, label, len);
    pObject->name[len] = '\0';
    pObject->class_id = CKO_PUBLIC_KEY;
    pObject->class_type = CKK_EC;
    pObject->attributes = pkcs11_key_public_attributes;
    pObject->count = pkcs11_key_public_attributes_count;
    pObject->data = NULL;
    pObject->size = 64;
}

/**
 * \brief Create a new object on the token in the specified session using the given attribute template
 */
CK_RV qti_pkcs11_object_create
(
    CK_SESSION_HANDLE    hSession,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phObject
)
{
    CK_RV rv;
    pkcs11_object_ptr pObject;
    CK_ATTRIBUTE_PTR pLabel = NULL;
    CK_OBJECT_CLASS_PTR pClass = NULL;
    CK_ATTRIBUTE_PTR pData = NULL;
    int i;
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession = NULL;

    rv = qti_pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    /* Look for supported/mandatory attributes */
    for (i = 0; i < ulCount; i++)
    {
        switch (pTemplate[i].type)
        {
        case CKA_LABEL:
            pLabel = &pTemplate[i];
            break;
        case CKA_CLASS:
            pClass = pTemplate[i].pValue;
            break;
        case CKA_VALUE:
        /* fall-through */
        case CKA_EC_POINT:
            pData = &pTemplate[i];
            break;
        default:
            break;
        }
    }

    rv = qti_pkcs11_object_alloc(&pObject);
    if (pObject)
    {
        switch (*pClass)
        {
        case CKO_PUBLIC_KEY:
            pObject->class_id = CKO_PUBLIC_KEY;
            pObject->slot = i;
            pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
            qti_pkcs11_config_init_public(pObject, pLabel->pValue, pLabel->ulValueLen);
            break;
        case CKO_PRIVATE_KEY:
            pObject->class_id = CKO_PRIVATE_KEY;
            pObject->slot = i;
            pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
            qti_pkcs11_config_init_private(pObject, pLabel->pValue, pLabel->ulValueLen);
            break;
        default:
            break;
        }
        if (CKR_OK == rv)
        {
            rv = qti_pkcs11_object_get_handle(pObject, phObject);
        }
    }

    return rv;
}

/**
 * \brief Destroy the specified object
 */
CK_RV qti_pkcs11_object_destroy(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    pkcs11_object_ptr pObject;
    CK_RV rv;
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession = NULL;

    rv = qti_pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = qti_pkcs11_object_check(&pObject, hObject);
    if (rv)
    {
        return rv;
    }

    if (pObject->flags & PKCS11_OBJECT_FLAG_DESTROYABLE)
    {
        return qti_pkcs11_object_free(pObject);
    }
    else
    {
        return CKR_ACTION_PROHIBITED;
    }
}

/* Interal function to clean up resources */
CK_RV qti_pkcs11_object_deinit(pkcs11_lib_ctx_ptr pContext)
{
    CK_RV rv = CKR_OK;
    int i;

    for (i = 0; i < PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        pkcs11_object_ptr pObj = pkcs11_object_cache[i].object;
        if (pObj)
        {
            CK_RV tmp = qti_pkcs11_object_free(pObj);
            if (!rv)
            {
                rv = tmp;
            }
        }
    }
    return rv;
}

CK_RV qti_pkcs11_find_get_attribute(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pObject;
    CK_ULONG i;
    CK_RV rv;

printf("%s %d\n",__func__, __LINE__);

    rv = qti_pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }
printf("%s %d\n",__func__, __LINE__);


    if (!pTemplate || !ulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }
printf("%s %d\n",__func__, __LINE__);


    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }
printf("%s %d\n",__func__, __LINE__);

#if 1
    rv = qti_pkcs11_object_check(&pObject, hObject);
    if (rv)
    {
        return rv;
    }
#endif
printf("%s %d\n",__func__, __LINE__);

    //return qti_pkcs11_attrib_fill(&pTemplate[0], (const CK_VOID_PTR)&cbTrue, sizeof(cbTrue));
#if 1
    for (i = 0; i < ulCount; i++)
    {
        pkcs11_attrib_model_ptr pAttribute = qti_pkcs11_find_attrib((const pkcs11_attrib_model_ptr)pObject->attributes,
                                                                pObject->count, &pTemplate[i]);
printf("%s %d\n",__func__, __LINE__);


        if (!pAttribute)
        {
            /* 2. Otherwise, if the specified value for the object is invalid(the object does not possess such an
               attribute), then the ulValueLen field in that triple is modified to hold the value CK_UNAVAILABLE_INFORMATION. */

            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            if (!rv)
            {
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
            }
        }
        else if (pAttribute->func)
        {
                /* Attribute function found so try to execute it */
                CK_RV temp = pAttribute->func(pObject, &pTemplate[i]);
                if (!rv)
                {
                    rv = temp;
                }
        }
        else
        {
            /* Assume if there is no function for the attribute we're keeping it private */
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            if (!rv)
            {
                rv = CKR_ATTRIBUTE_SENSITIVE;
            }
        }
    }
printf("%s %d\n",__func__, __LINE__);
#endif

    return rv;
}

CK_RV qti_pkcs11_key_generate_pair
(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
    CK_ULONG             ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
    CK_ULONG             ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
    CK_ATTRIBUTE_PTR pName = NULL;
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pPublic = NULL;
    pkcs11_object_ptr pPrivate = NULL;
    int i;
    CK_RV rv = CKR_OK;

    rv = qti_pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pMechanism || !pPublicKeyTemplate || !ulPublicKeyAttributeCount ||
        !pPrivateKeyTemplate || !ulPrivateKeyAttributeCount ||
        !phPublicKey || !phPrivateKey)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    /* @todo Perform the various mechanism and key attribute checks */

    if (CKM_EC_KEY_PAIR_GEN != pMechanism->mechanism)
    {
        return CKR_MECHANISM_INVALID;
    }


    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;    /* Unless specified assume private key object */

    /* Match Name and Class */
    for (i = 0; i < ulPrivateKeyAttributeCount; i++)
    {
        if (CKA_LABEL == pPrivateKeyTemplate[i].type)
        {
            pName = &pPrivateKeyTemplate[i];
            break;
        }
    }

    if (!pName || pName->ulValueLen > PKCS11_MAX_LABEL_SIZE)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }

    /* Must create two new objects - a public and private key */

    if (CKR_OK == rv)
    {
        rv = qti_pkcs11_object_alloc(&pPrivate);
    }

    if (CKR_OK == rv)
    {
        rv = qti_pkcs11_object_alloc(&pPublic);
    }

    if (CKR_OK == rv)
    {
        if (!pPublic || !pPrivate)
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
    }

    if (CKR_OK == rv)
    {
        pPrivate->class_id = CKO_PRIVATE_KEY;
        qti_pkcs11_config_init_private(pPrivate, pName->pValue, pName->ulValueLen);
    }

if (CKR_OK == rv)
    {
        pPublic->slot = pPrivate->slot;
        pPublic->flags = pPrivate->flags;
        memcpy(pPublic->name, pName->pValue, pName->ulValueLen);
        pPublic->class_id = CKO_PUBLIC_KEY;
        pPublic->class_type = CKK_EC;
        pPublic->attributes = pkcs11_key_public_attributes;
        pPublic->count = pkcs11_key_public_attributes_count;
        pPublic->size = 64;
    }

    if (CKR_OK == rv)
    {
        qti_pkcs11_object_get_handle(pPrivate, phPrivateKey);
        qti_pkcs11_object_get_handle(pPublic, phPublicKey);
    }
    else
    {
        if (pPrivate)
        {
            qti_pkcs11_object_free(pPrivate);
        }
        if (pPublic)
        {
            qti_pkcs11_object_free(pPublic);
        }
    }

    return rv;
}
