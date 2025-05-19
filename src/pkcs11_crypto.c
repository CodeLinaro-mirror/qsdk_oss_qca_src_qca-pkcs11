/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include "pkcs11_crypto.h"
#include "pkcs11_session.h"
#include "pkcs11_init.h"
#include "pkcs11_object.h"

const char *qseecom_device = "/dev/qseecom_device";

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
    struct ecdsa_sign sign = {0};
    CK_RV rv;
    int fd, i;

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
    if ((pData == NULL) || (pSignature == NULL) || !ulDataLen || !pulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    for(i=0; i<ulDataLen; i=i+4)
	    printf("%x", *((unsigned int *)pData + 1));
    sign.key_handle = pSession->active_object;
    sign.data = pData;
    sign.data_len = ulDataLen;
    sign.signature = pSignature;

    fd = open(qseecom_device, O_RDWR);
    if (fd < 0) {
	    printf("Cannot open device file: %s\n", qseecom_device);
	    return CKR_DEVICE_ERROR;
    }

    rv = ioctl(fd, QSEECOM_ECDSA_SIGN, &sign);
    if (rv || sign.result) {
	printf("Failed on Data Sign, rv=%ld, result=%u\n, sig len %u", rv, sign.result, sign.signature_out_len);
	rv = CKR_FUNCTION_FAILED;
	goto close_fd;
    }

    *pulSignatureLen = sign.signature_out_len;

close_fd:
    close(fd);

    return rv;
}

CK_RV qti_pkcs11_signature_verify_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
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

CK_RV qti_pkcs11_signature_verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    struct ecdsa_verify verify;
    CK_RV rv;
    int fd;

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

    if ((pData == NULL) || (pSignature == NULL) || !ulDataLen || !ulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    verify.key_handle = pSession->active_object;
    verify.data = pData;
    verify.data_len = ulDataLen;
    verify.signature = pSignature;
    verify.signature_len = ulSignatureLen;

    fd = open(qseecom_device, O_RDWR);
    if (fd < 0) {
	    printf("Cannot open device file: %s\n", qseecom_device);
	    return CKR_DEVICE_ERROR;
    }

    rv = ioctl(fd, QSEECOM_ECDSA_VERIFY, &verify);
    if (rv || verify.result) {
	printf("Failed on Data Verify, rv=%lu, result=%u\n", rv, verify.result);
	rv = CKR_FUNCTION_FAILED;
    }

    close(fd);

    return rv;
}
