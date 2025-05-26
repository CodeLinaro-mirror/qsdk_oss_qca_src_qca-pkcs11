/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include "pkcs11_session.h"
#include "pkcs11_init.h"
#include <string.h>
#include <stdio.h>

typedef struct pkcs11_template_st {
        unsigned long allocated;
        unsigned int nattr;
        CK_ATTRIBUTE attrs[32];
} PKCS11_TEMPLATE;


unsigned int qti_pkcs11_addattr(PKCS11_TEMPLATE *tmpl, int type, void *data, size_t size)
{
        unsigned int n = tmpl->nattr;
        CK_ATTRIBUTE_PTR ap;

        ap = &tmpl->attrs[tmpl->nattr++];
        ap->type = type;
        ap->pValue = data;
        ap->ulValueLen = (CK_ULONG)size;
        return n;
}

void qti_pkcs11_addattr_bool(PKCS11_TEMPLATE *tmpl, int type, int value)
{
        static CK_BBOOL _true = CK_TRUE;
        static CK_BBOOL _false = CK_FALSE;
        qti_pkcs11_addattr(tmpl, type, value ? &_true : &_false, sizeof(CK_BBOOL));
}

void qti_pkcs11_addattr_s(PKCS11_TEMPLATE *tmpl, int type, const char *s)
{
        qti_pkcs11_addattr(tmpl, type, (void *)s, s ? strlen(s) : 0);
}

//#define pkcs11_addattr_var(_tmpl, _type, _var) pkcs11_addattr(_tmpl, _type, &(_var), sizeof(_var))

/* Commenting the dummy key support
static void qti_pkcs11_generate_key_dummy(CK_SESSION_HANDLE session)
{

        PKCS11_TEMPLATE tmpl = {0};
        CK_OBJECT_HANDLE object;
        CK_KEY_TYPE key_type_ECDSA = CKK_ECDSA;
	unsigned long class_type = CKO_PRIVATE_KEY;
	char *label;
        unsigned char *id;
        size_t id_len;

	label = "PRIVATE";
	id = "0";
	id_len = sizeof(id);

//        qti_pkcs11_addattr_var(&tmpl, CKA_CLASS, CKO_PRIVATE_KEY);

	qti_pkcs11_addattr(&tmpl, CKA_CLASS, &class_type,sizeof(class_type));

        if (label)
                qti_pkcs11_addattr_s(&tmpl, CKA_LABEL, label);

        if (id && id_len)
                qti_pkcs11_addattr(&tmpl, CKA_ID, id, id_len);

        qti_pkcs11_addattr_bool(&tmpl, CKA_TOKEN, TRUE);
        qti_pkcs11_addattr_bool(&tmpl, CKA_PRIVATE, TRUE);
        qti_pkcs11_addattr_bool(&tmpl, CKA_SENSITIVE, TRUE);
        qti_pkcs11_addattr_bool(&tmpl, CKA_DECRYPT, TRUE);
        qti_pkcs11_addattr_bool(&tmpl, CKA_SIGN, TRUE);
        qti_pkcs11_addattr_bool(&tmpl, CKA_UNWRAP, TRUE);
        qti_pkcs11_addattr(&tmpl, CKA_KEY_TYPE, &key_type_ECDSA, sizeof(key_type_ECDSA));
//        qti_pkcs11_addattr_var(&tmpl,  CKA_KEY_TYPE, key_type_ECDSA);

        C_CreateObject(session, tmpl.attrs, tmpl.nattr, &object);
} */

/**
 * \defgroup pkcs11 Session Management (pkcs11_)
   @{ */
static pkcs11_session_ctx pkcs11_session_cache[PKCS11_MAX_SESSIONS_ALLOWED];

static pkcs11_session_ctx_ptr qti_pkcs11_allocate_session_context(void)
{
    pkcs11_session_ctx_ptr rv = NULL_PTR;
    CK_ULONG i;

    for (i = 0; i < PKCS11_MAX_SESSIONS_ALLOWED; i++)
    {
        if (!pkcs11_session_cache[i].initialized)
        {
            rv = &pkcs11_session_cache[i];
            break;
        }
    }

    return rv;
}

pkcs11_session_ctx_ptr qti_pkcs11_get_session_context(CK_SESSION_HANDLE hSession)
{
    return (pkcs11_session_ctx_ptr)hSession;
}

/**
 * \brief Check if the session is initialized properly
 */
CK_RV qti_pkcs11_session_check(pkcs11_session_ctx_ptr * pSession, CK_SESSION_HANDLE hSession)
{
    pkcs11_session_ctx_ptr ctx = qti_pkcs11_get_session_context(hSession);
    CK_RV rv = CKR_SESSION_HANDLE_INVALID;

    if (ctx)
    {
        if (ctx->initialized)
        {
            rv = CKR_OK;
        }
        else
        {
            rv = CKR_SESSION_CLOSED;
        }
    }

    if (pSession)
    {
        if (rv)
        {
            *pSession = NULL_PTR;
        }
        else
        {
            *pSession = ctx;
        }
    }
    return rv;
}

CK_RV qti_pkcs11_session_open(
    CK_SLOT_ID            slotID,
    CK_FLAGS              flags,
    CK_VOID_PTR           pApplication,
    CK_NOTIFY             notify,
    CK_SESSION_HANDLE_PTR phSession
    )
{
    pkcs11_lib_ctx_ptr lib_ctx = qti_pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;
    pkcs11_session_ctx_ptr session_ctx;

    ((void)notify);
    ((void)pApplication);

    if (!lib_ctx || !lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!phSession)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* See PKCS11 Sec 5.6.1 - Legacy reaons */
    if (!(flags & CKF_SERIAL_SESSION))
    {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    slot_ctx = qti_pkcs11_slot_get_context(lib_ctx, slotID);

    if (!slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    if (!slot_ctx->initialized)
    {
        return CKR_TOKEN_NOT_RECOGNIZED;
    }

    /* Get a new session context */
    session_ctx = qti_pkcs11_allocate_session_context();

    /* Check that a session was created */
    if (!session_ctx)
    {
        return CKR_HOST_MEMORY;
    }

    /* Initialize the session */
    session_ctx->slot = slot_ctx;
    session_ctx->initialized = TRUE;

    /* Assign the session handle */
    session_ctx->handle = (CK_SESSION_HANDLE)session_ctx;

    *phSession = session_ctx->handle;

    /* notify callback is not yet handled, Fix it later */

    /* Generate dummy private key for this session */
//  qti_pkcs11_generate_key_dummy((CK_SESSION_HANDLE)session_ctx);
    qti_pkcs11_config_load_objects(slot_ctx);

    return CKR_OK;
}

CK_RV qti_pkcs11_session_close(CK_SESSION_HANDLE hSession)
{
    pkcs11_lib_ctx_ptr lib_ctx = qti_pkcs11_get_context();
    pkcs11_session_ctx_ptr session_ctx = qti_pkcs11_get_session_context(hSession);
    pkcs11_slot_ctx_ptr slot_ctx;

    if (!lib_ctx || !lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!session_ctx)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx->initialized)
    {
        return CKR_SESSION_CLOSED;
    }

    /* Get the slot */
    slot_ctx = (pkcs11_slot_ctx_ptr)session_ctx->slot;

    if (slot_ctx)
    {
        /* Clear the objects associated with this session */
    }

    /* Free the session */
    memset(session_ctx, 0, sizeof(pkcs11_session_ctx));

    return CKR_OK;
}

/**
 * \brief Close all sessions for a given slot - not actually all open sessions
 */
CK_RV qti_pkcs11_session_closeall(CK_SLOT_ID slotID)
{
    pkcs11_lib_ctx_ptr lib_ctx = qti_pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;

    if (!lib_ctx || !lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    slot_ctx = qti_pkcs11_slot_get_context(lib_ctx, slotID);

    if (!slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    /* If there were the ability to have multiple sessions open for a slot then
       we'd loop over the sessions and close them in order*/
    int i;
    for (i = 0; i < PKCS11_MAX_SESSIONS_ALLOWED; i++)
    {
        qti_pkcs11_session_close(pkcs11_session_cache[i].handle);
    }

    return CKR_OK;
}

/**
 * \brief Obtains information about a particular session
 */
CK_RV qti_pkcs11_session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    pkcs11_lib_ctx_ptr lib_ctx = qti_pkcs11_get_context();
    pkcs11_session_ctx_ptr session_ctx = qti_pkcs11_get_session_context(hSession);
    pkcs11_slot_ctx_ptr slot_ctx;

    if (!lib_ctx || !lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!pInfo)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!session_ctx)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx->initialized)
    {
        return CKR_SESSION_CLOSED;
    }

    pInfo->state = session_ctx->state;
    pInfo->ulDeviceError = session_ctx->error;

    slot_ctx = session_ctx->slot;
    if (slot_ctx)
    {
        pInfo->slotID = slot_ctx->slot_id;
    }

    pInfo->flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;

    return CKR_OK;
}

CK_RV qti_pkcs11_session_login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    pkcs11_lib_ctx_ptr lib_ctx = qti_pkcs11_get_context();
    pkcs11_session_ctx_ptr session_ctx = qti_pkcs11_get_session_context(hSession);

    if (!lib_ctx || !lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!pPin || !ulPinLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!session_ctx)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx->initialized)
    {
        return CKR_SESSION_CLOSED;
    }

    /* Just return success, We do not really verify credentials */
    return CKR_OK;
}
