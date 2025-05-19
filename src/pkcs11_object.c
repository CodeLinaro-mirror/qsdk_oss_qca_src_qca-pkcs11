/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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
//static unsigned int objects_used;

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
printf("%s %d %d\n",__func__, __LINE__, i);
        if (!pkcs11_object_cache[i].object)
        {
printf("%s %d %d\n",__func__, __LINE__, i);

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

    return i;
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

    if (pAttribute->pValue)
    {
        /* 1. If the specified attribute(i.e., the attribute specified by the type field) for the object cannot be revealed
           because the object is sensitive or unextractable, then the ulValueLen field in that triple is modified to
           hold the value CK_UNAVAILABLE_INFORMATION. //if (!rv) rv = CKR_ATTRIBUTE_SENSITIVE; */
	printf("#### %s pAttribute->type %d pAttribute->pValue 0x%x pAttribute->pValuelen %u data 0x%x \n", __func__, pAttribute->type , pAttribute->pValue, pAttribute->ulValueLen, (int *)pData);
        if (ulSize <= pAttribute->ulValueLen)
        {
            /* 4. Otherwise, if the length specified in ulValueLen is large enough to hold the value of the specified
               attribute for the object, then that attribute is copied into the buffer located at pValue */

            if (pData)
            {
                memcpy(pAttribute->pValue, pData, ulSize);
            }
            else
            {
                /* This case isn't covered by the PKCS11 specification as it always assumes that the internals of the
                   library should be rational about providing some data if an attribute is matched. */
                memset(pAttribute->pValue, 0, pAttribute->ulValueLen);
            }
        }
        else
        {
            /* 5. Otherwise, the ulValueLen field is modified to hold the value CK_UNAVAILABLE_INFORMATION. */
            pAttribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;

            return CKR_BUFFER_TOO_SMALL;
        }
    }

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

CK_RV pkcs11_key_get_private_key(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
	printf("%s %d\n",__func__, __LINE__);
//       pkcs11_attrib_fill(pAttribute, /* buffer holding key */, /* sizeof buffer */);
}

CK_RV pkcs11_key_get_public_key(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
	printf("%s %d\n",__func__, __LINE__);
//       pkcs11_attrib_fill(pAttribute, /* buffer holding key */, /* sizeof buffer */);
}

static const CK_UTF8CHAR pkcs11_key_ec_params[] = {
	0x30,0x82,0x01,0x57,0x02,0x01,0x01,0x30,0x3C,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x01,0x01,0x02,0x31,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
	0xFF,0xFF,0xFF,0x30,0x7B,0x04,0x30,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFC,0x04,0x30,0xB3,0x31,0x2F,0xA7,0xE2,0x3E,0xE7,0xE4,0x98,
	0x8E,0x05,0x6B,0xE3,0xF8,0x2D,0x19,0x18,0x1D,0x9C,0x6E,0xFE,0x81,0x41,0x12,0x03,0x14,0x08,0x8F,0x50,0x13,0x87,0x5A,0xC6,0x56,0x39,0x8D,0x8A,0x2E,0xD1,0x9D,0x2A,0x85,
	0xC8,0xED,0xD3,0xEC,0x2A,0xEF,0x03,0x15,0x00,0xA3,0x35,0x92,0x6A,0xA3,0x19,0xA2,0x7A,0x1D,0x00,0x89,0x6A,0x67,0x73,0xA4,0x82,0x7A,0xCD,0xAC,0x73,0x04,0x61,0x04,0xAA,
	0x87,0xCA,0x22,0xBE,0x8B,0x05,0x37,0x8E,0xB1,0xC7,0x1E,0xF3,0x20,0xAD,0x74,0x6E,0x1D,0x3B,0x62,0x8B,0xA7,0x9B,0x98,0x59,0xF7,0x41,0xE0,0x82,0x54,0x2A,0x38,0x55,0x02,
	0xF2,0x5D,0xBF,0x55,0x29,0x6C,0x3A,0x54,0x5E,0x38,0x72,0x76,0x0A,0xB7,0x36,0x17,0xDE,0x4A,0x96,0x26,0x2C,0x6F,0x5D,0x9E,0x98,0xBF,0x92,0x92,0xDC,0x29,0xF8,0xF4,0x1D,
	0xBD,0x28,0x9A,0x14,0x7C,0xE9,0xDA,0x31,0x13,0xB5,0xF0,0xB8,0xC0,0x0A,0x60,0xB1,0xCE,0x1D,0x7E,0x81,0x9D,0x7A,0x43,0x1D,0x7C,0x90,0xEA,0x0E,0x5F,0x02,0x31,0x00,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC7,0x63,0x4D,0x81,0xF4,0x37,0x2D,0xDF,0x58,0x1A,
	0x0D,0xB2,0x48,0xB0,0xA7,0x7A,0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73,0x02,0x01,0x01 };

CK_RV pkcs11_key_get_ec_params(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    return qti_pkcs11_attrib_fill(pAttribute, (CK_VOID_PTR)pkcs11_key_ec_params, sizeof(pkcs11_key_ec_params));
}

CK_RV pkcs11_key_get_ec_point(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
	CK_UTF8CHAR ec_asn1_key[] = {
	0x04, 0x61, 0x04, 0xCD, 0x6C, 0xA1, 0xA1, 0x15, 0x8C, 0x38, 0x69, 0x73, 0xA7, 0x2F, 0xA1, 0x3F,
	0xF0, 0x79, 0xBF, 0x6A, 0xAC, 0x12, 0x2D, 0xA2, 0x92, 0xF1, 0x11, 0x17, 0xD9, 0x95, 0x55, 0x7C,
	0xFA, 0x92, 0x8A, 0x60, 0x75, 0xC9, 0x92, 0x75, 0x2C, 0x73, 0x6C, 0xCC, 0x59, 0xEC, 0xC9, 0x8A,
	0x2B, 0x0E, 0x7F, 0x75, 0xE7, 0x5A, 0xD2, 0x34, 0x92, 0xC7, 0x15, 0x2D, 0x72, 0xD3, 0x07, 0x20,
	0xD6, 0x8D, 0xBF, 0x5B, 0x18, 0xF9, 0x9F, 0x7D, 0x9E, 0xA7, 0x4A, 0x29, 0x76, 0x75, 0x35, 0x8D,
	0x59, 0xBB, 0x84, 0xBB, 0x9A, 0xF6, 0x09, 0xF0, 0xB9, 0x8F, 0xDE, 0xE3, 0x7B, 0xA8, 0x61, 0x4E,
	0x08, 0x54, 0x68 };
    
	return qti_pkcs11_attrib_fill(pAttribute, ec_asn1_key, sizeof(ec_asn1_key));
}

static const CK_MECHANISM_TYPE pkcs11_key_508_public_mech[] = {
    CKM_ECDSA,
    CKM_ECDSA_SHA256
};
 
static const CK_MECHANISM_TYPE pkcs11_key_508_private_mech[] = {
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256
};
 
CK_RV pkcs11_key_get_allowed_mechanisms_priv(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
            return qti_pkcs11_attrib_fill(pAttribute, (CK_VOID_PTR)pkcs11_key_508_private_mech,
                                      sizeof(pkcs11_key_508_private_mech));
}
 
CK_RV pkcs11_key_get_allowed_mechanisms_pub(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
            return qti_pkcs11_attrib_fill(pAttribute, (CK_VOID_PTR)pkcs11_key_508_public_mech,
                                      sizeof(pkcs11_key_508_public_mech));
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
    { CKA_ID,                  NULL_PTR                                                                   },
    { CKA_SIGN,                qti_pkcs11_attrib_true                                                                    },
    { CKA_VALUE,              	NULL_PTR }, //pkcs11_key_get_private_key                                  },
    { CKA_DECRYPT,		qti_pkcs11_attrib_true	},
    { CKA_UNWRAP,		qti_pkcs11_attrib_true        },
    { CKA_DERIVE,		qti_pkcs11_attrib_false        },
    { CKA_EXTRACTABLE,		qti_pkcs11_attrib_false        },
    { CKA_NEVER_EXTRACTABLE,	qti_pkcs11_attrib_false        },
    { CKA_SENSITIVE,		qti_pkcs11_attrib_true        },
    { CKA_ALWAYS_SENSITIVE,	qti_pkcs11_attrib_false        },
    { CKA_ALWAYS_AUTHENTICATE,	qti_pkcs11_attrib_false		},
    { CKA_LOCAL,		qti_pkcs11_attrib_false		},
    { CKA_EC_PARAMS,		pkcs11_key_get_ec_params	},
    { CKA_EC_POINT,		pkcs11_key_get_ec_point		},
    { CKA_ALLOWED_MECHANISMS,	pkcs11_key_get_allowed_mechanisms_priv },
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
    { CKA_VALUE,               pkcs11_key_get_public_key                                                                              },
    { CKA_DERIVE,		NULL_PTR        },
    { CKA_WRAP,			NULL_PTR        },
    { CKA_ENCRYPT,		NULL_PTR	},
    { CKA_VERIFY,		NULL_PTR        },
    { CKA_LOCAL,		qti_pkcs11_attrib_false        },
    { CKA_EC_PARAMS,		pkcs11_key_get_ec_params	},
    { CKA_EC_POINT,		pkcs11_key_get_ec_point		},
    { CKA_ALLOWED_MECHANISMS,	pkcs11_key_get_allowed_mechanisms_pub},
};

const CK_ULONG pkcs11_key_private_attributes_count = sizeof(pkcs11_key_private_attributes)/sizeof(pkcs11_key_private_attributes[0]);
const CK_ULONG pkcs11_key_public_attributes_count = sizeof(pkcs11_key_public_attributes)/sizeof(pkcs11_key_public_attributes[0]);

static void qti_pkcs11_save_obj_store(pkcs11_slot_ctx_ptr pSlot, char *objtype, pkcs11_object_ptr pObject, int index)
{
    FILE* fp;
    char filename[200];
    char cwd[100];
    int i;

    if (!getcwd(cwd, sizeof(cwd)) != NULL) {
	 printf("Error: Unable to save in cwd \n");
  	 return;
    }
printf("%s type %s\n",__func__, objtype);
    //TBD
//    i = objects_used - 1;

/*    for (i = 0; i < PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (!(pObject->flags & (1 << i)))
             break;
    }*/

printf("%s %d i %d\n",__func__, __LINE__, index);

    if (index < PKCS11_MAX_OBJECTS_ALLOWED)
    {
        (void)snprintf(filename, sizeof(filename), "%s%d.%d.conf", cwd, pSlot->slot_id, index);
        fp = fopen(filename, "wb");
        if (fp)
        {
printf("%s %d\n",__func__, __LINE__);
            fprintf(fp, "type = %s\n", objtype);
            fprintf(fp, "label = %s\n", pObject->name);
            fclose(fp);
        }
    }
}


void qti_pkcs11_config_init_private(pkcs11_object_ptr pObject, char * label, size_t len)
//* Static file size of max 1000 bytes to hold object attributes */
{
printf("%s %d\n",__func__, __LINE__);
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
    pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
//    objects_used++;
}

void qti_pkcs11_config_init_public(pkcs11_object_ptr pObject, char * label, size_t len)
{
printf("%s %d\n",__func__, __LINE__);
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
    pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
//    objects_used++;
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
    CK_ATTRIBUTE_PTR pValue = NULL;
    int i, index;
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession = NULL;
    pkcs11_slot_ctx_ptr slot_ctx;

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
printf("%s %d pTemplate[i].type 0x%x\n",__func__, __LINE__, pTemplate[i].type);
        switch (pTemplate[i].type)
        {
        case CKA_LABEL:
            pLabel = &pTemplate[i];
            break;
        case CKA_CLASS:
            pClass = pTemplate[i].pValue;
            break;
        case CKA_VALUE:
	    pValue = &pTemplate[i];
	    printf("%s pValue_len %lu pValue 0x%x\n",__func__, pValue->ulValueLen, (unsigned int *)pValue->pValue);
        /* Fix this to save in the file */
        case CKA_EC_POINT:
            pData = &pTemplate[i];
            break;
        default:
            break;
        }
    }

    slot_ctx = (pkcs11_slot_ctx_ptr)pSession->slot;

    index = qti_pkcs11_object_alloc(&pObject);
    if (pObject)
    {
        switch (*pClass)
        {
        case CKO_PUBLIC_KEY:
            pObject->class_id = CKO_PUBLIC_KEY;
            pObject->slot = i;
            pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
            qti_pkcs11_config_init_public(pObject, pLabel->pValue, pLabel->ulValueLen);
	    qti_pkcs11_save_obj_store(slot_ctx, "public", pObject, index);
            break;
        case CKO_PRIVATE_KEY:
            pObject->class_id = CKO_PRIVATE_KEY;
            pObject->slot = i;
            pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
            qti_pkcs11_config_init_private(pObject, pLabel->pValue, pLabel->ulValueLen);
	    qti_pkcs11_save_obj_store(slot_ctx, "private", pObject, index);
            break;
        default:
            break;
        }
//        if (CKR_OK == rv)
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

    if (!pTemplate || !ulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

#if 1
    rv = qti_pkcs11_object_check(&pObject, hObject);
    if (rv)
    {
        return rv;
    }
#endif

    //return qti_pkcs11_attrib_fill(&pTemplate[0], (const CK_VOID_PTR)&cbTrue, sizeof(cbTrue));
#if 1
    for (i = 0; i < ulCount; i++)
    {
        pkcs11_attrib_model_ptr pAttribute = qti_pkcs11_find_attrib((const pkcs11_attrib_model_ptr)pObject->attributes,
                                                                pObject->count, &pTemplate[i]);

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
//	printf("##### %s %d #### type %d value %d value %s ulValueLen %d\n", __func__, __LINE__, pTemplate[i].type, *(int *)pTemplate[i].pValue, (char *)pTemplate[i].pValue, pTemplate[i].ulValueLen);
	if (pTemplate[i].pValue != NULL)
		printf("##### %s %d #### type 0x%x Value %d char %s ValueLen %d\n", __func__, __LINE__, pTemplate[i].type, *(unsigned char *)pTemplate[i].pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
	else
		printf("##### %s %d #### type 0x%x  ValueLen %d\n", __func__, __LINE__, pTemplate[i].type, pTemplate[i].ulValueLen);
    }
#endif

    return rv;
}

/* Static file size of max 1000 bytes to hold object attributes */
#define MAX_OBJ_FILE_SZ 1000

static size_t qti_pkcs11_config_load_file(FILE* fp, char * buffer)
{
    size_t size = 0;

    if (buffer)
    {
        /* Get file size */
        fseek(fp, 0L, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        memset(buffer, 0, size);
        if (size != fread(buffer, 1, size, fp))
             size = 0;
    }

    return size;
}


/* Parse a buffer into key value pairs. Return value should be an even value */
static int qti_pkcs11_config_parse_buffer(char* buffer, size_t len, int argc, char* argv[])
{
    char* s;
    int args = 0;
    bool comment = FALSE;
    bool arg = FALSE;
    bool v = FALSE;

    if (!buffer || !len || !argc || !argv)
    {
        return 0;
    }

    for (s = buffer; s < (buffer + len) && args < argc; s++)
    {
        switch (*s)
        {
        case '\n':
        case '\r':
            /* End the line*/
            if (arg && !v && !comment)
            {
                /* Everything must be a key value pair */
                return 0;
            }
            else
            {
                comment = FALSE;
                v = FALSE;
                arg = FALSE;
                *s = '\0';
            }
            break;
        case '=':
            v = TRUE;
        case ' ':
        case '\t':
            *s = '\0';
            arg = 0;
            break;
        default:
            if (!comment)
            {
                if (*s == '#')
                {
                    comment = 1;
                }
                else if (!arg)
                {
                    argv[args++] = s;
                    arg = TRUE;
                }
            }
            break;
        }
    }

    if (args & 0x1)
    {
        /* Parsing error occured */
        args = 0;
    }

    return args;
}

static CK_RV qti_pkcs11_config_parse_object_file(pkcs11_slot_ctx_ptr slot_ctx, CK_BYTE slot, int argc, char * argv[])
{
    CK_RV rv;
    int i;
    pkcs11_object_ptr pObject = NULL;
    bool privkey = FALSE;

    rv = qti_pkcs11_object_alloc(&pObject);
    if (pObject)
    {
        pObject->slot = slot;
        pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
        memset(pObject->name, 0, sizeof(pObject->name));
    }

    for (i = 0; i < argc; i += 2)
    {
        if (!strcmp(argv[i], "type"))
        {
            if (!strcmp(argv[i + 1], "private"))
            {
                privkey = TRUE;
printf("%s type = private\n",__func__);
                qti_pkcs11_config_init_private(pObject, "", 0);
            }
            else if (!strcmp(argv[i + 1], "public"))
            {
printf("%s type = public\n",__func__);
                qti_pkcs11_config_init_public(pObject, "", 0);
            }
        }
        else if (!strcmp(argv[i], "label"))
        {
printf("%s label = %s\n",__func__, argv[i + 1]);
            strlcpy(pObject->name, argv[i + 1], sizeof(pObject->name));
        }
    }

#ifdef XXX //TBD
    if (!rv && privkey)
    {
printf("%s %d\n",__func__, __LINE__);
        /* Have to create a public copy of private keys */
        pkcs11_object_ptr pPubkey = NULL;
        rv = qti_pkcs11_object_alloc(&pPubkey);
        if (pPubkey)
        {
printf("%s %d\n",__func__, __LINE__);
            pPubkey->slot = slot;
            pPubkey->flags = pObject->flags;
            qti_pkcs11_config_init_public(pPubkey, pObject->name, strlen(pObject->name));
        }
        else
        {
            qti_pkcs11_object_free(pObject);
        }
    }
#endif

    return rv;
}

/* Load objects from the file store for a given slot */
CK_RV qti_pkcs11_config_load_objects(pkcs11_slot_ctx_ptr pSlot)
{
    FILE* fp;
    char buffer[MAX_OBJ_FILE_SZ];
    size_t buflen;
    char* argv[PKCS11_MAX_OBJECTS_ALLOWED + 1];
    int argc = 0;
    char filename[200];
    int j;
    CK_RV rv;
    char cwd[100];

printf("%s %d\n",__func__, __LINE__);

    if (!getcwd(cwd, sizeof(cwd)) != NULL) {
	 printf("Error: Unable to save in cwd \n");
  	 return;
    }

    for (j = 0; j < PKCS11_MAX_OBJECTS_ALLOWED; j++)
    {
            (void)snprintf(filename, sizeof(filename), "%s%d.%d.conf", cwd, pSlot->slot_id, j);
            fp = fopen(filename, "rb");

            if (fp)
            {
                buflen = qti_pkcs11_config_load_file(fp, buffer);
                fclose(fp);
                fp = NULL;

                /* Remove the slot from the free list*/
                pSlot->flags &= ~(1 << j);

                if (0 < buflen)
                {
                    if (0 < (argc = qti_pkcs11_config_parse_buffer(buffer, buflen, sizeof(argv) / sizeof(argv[0]), argv)))
                    {
                        rv = qti_pkcs11_config_parse_object_file(pSlot, j, argc, argv);
                    }
                    else
                    {
                        PKCS11_DEBUG("Failed to parse the slot configuration file");
                    }
                }
            }
     }
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
    pkcs11_slot_ctx_ptr slot_ctx;
    CK_RV rv = CKR_OK;
    int i, pub_index, prv_index;

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
        prv_index = qti_pkcs11_object_alloc(&pPrivate);
    }

    if (CKR_OK == rv)
    {
        pub_index = qti_pkcs11_object_alloc(&pPublic);
    }

    if (CKR_OK == rv)
    {
        if (!pPublic || !pPrivate)
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
    }

    slot_ctx = (pkcs11_slot_ctx_ptr)pSession->slot;

    if (CKR_OK == rv)
    {
        pPrivate->class_id = CKO_PRIVATE_KEY;
        qti_pkcs11_config_init_private(pPrivate, pName->pValue, pName->ulValueLen);
	qti_pkcs11_save_obj_store(slot_ctx, "private", pPrivate, prv_index);
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
	pPublic->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;

        qti_pkcs11_config_init_public(pPublic, pName->pValue, pName->ulValueLen);
        qti_pkcs11_save_obj_store(slot_ctx, "public", pPublic, pub_index);
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
