/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include "pkcs11_crypto.h"
#include "pkcs11_session.h"
#include "pkcs11_init.h"
#include "pkcs11_object.h"

CK_RV qti_pkcs11_token_init(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	/* Single static slot/token active by default */
	return CKR_OK;
}

CK_RV qti_pkcs11_slot_init(CK_SLOT_ID slotID)
{
	/*
	 * For TA representing the slot/token, TA gets loaded
	 * during boot, so nothing needs to be done
	 */
	return CKR_OK;
}

CK_RV qti_pkcs11_signature_sign_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pObject;
    CK_RV rv;

    rv = qti_pkcs11_init_check(NULL_PTR, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = qti_pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = qti_pkcs11_object_check(&pObject, hKey);
    if (rv)
    {
        return rv;
    }

    pSession->active_object = hKey;

    return CKR_OK;
}

CK_RV qti_pkcs11_signature_sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;

    ((void)ulDataLen);

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

    rv = qti_pkcs11_object_check(&pKey, pSession->active_object);
    if (rv)
    {
        return rv;
    }

   /* Check parameters */
    if (pulSignatureLen)
    {
        if (pSignature)
        {
            /*
	     * status = , Fill in the ioctl here with  pSession->active_object , infact since we are overriding the key, it should not matter,
             * please remove this comment after adding the ioctl

            if (status)
            {
                return CKR_FUNCTION_FAILED;
            }
	    */
        }
    }
    else
    {
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}
