/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */
/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */
#include "pkcs11.h"
#include <stdbool.h>
#include <stddef.h>
#include "cryptoki.h"
#include "pkcs11_debug.h"
#include "pkcs11_mech.h"

static const CK_FUNCTION_LIST pkcs11FunctionList = {
	.version = {
		.major = CRYPTOKI_VERSION_MAJOR,
		.minor = CRYPTOKI_VERSION_MINOR,
	},
	.C_Initialize = C_Initialize,
	.C_Finalize = C_Finalize,
	.C_GetInfo = C_GetInfo,
	.C_GetFunctionList = C_GetFunctionList,
	.C_GetSlotList = C_GetSlotList,
	.C_GetSlotInfo = C_GetSlotInfo,
	.C_GetTokenInfo = C_GetTokenInfo,
	.C_GetMechanismList = C_GetMechanismList,
	.C_GetMechanismInfo = C_GetMechanismInfo,
	.C_InitToken = C_InitToken,
	.C_InitPIN = C_InitPIN,
	.C_SetPIN = C_SetPIN,
	.C_OpenSession = C_OpenSession,
	.C_CloseSession = C_CloseSession,
	.C_CloseAllSessions = C_CloseAllSessions,
	.C_GetSessionInfo = C_GetSessionInfo,
	.C_GetOperationState = C_GetOperationState,
	.C_SetOperationState = C_SetOperationState,
	.C_Login = C_Login,
	.C_Logout = C_Logout,
	.C_CreateObject = C_CreateObject,
	.C_CopyObject = C_CopyObject,
	.C_DestroyObject = C_DestroyObject,
	.C_GetObjectSize = C_GetObjectSize,
	.C_GetAttributeValue = C_GetAttributeValue,
	.C_SetAttributeValue = C_SetAttributeValue,
	.C_FindObjectsInit = C_FindObjectsInit,
	.C_FindObjects = C_FindObjects,
	.C_FindObjectsFinal = C_FindObjectsFinal,
	.C_EncryptInit = C_EncryptInit,
	.C_Encrypt = C_Encrypt,
	.C_EncryptUpdate = C_EncryptUpdate,
	.C_EncryptFinal = C_EncryptFinal,
	.C_DecryptInit = C_DecryptInit,
	.C_Decrypt = C_Decrypt,
	.C_DecryptUpdate = C_DecryptUpdate,
	.C_DecryptFinal = C_DecryptFinal,
	.C_DigestInit = C_DigestInit,
	.C_Digest = C_Digest,
	.C_DigestUpdate = C_DigestUpdate,
	.C_DigestKey = C_DigestKey,
	.C_DigestFinal = C_DigestFinal,
	.C_SignInit = C_SignInit,
	.C_Sign = C_Sign,
	.C_SignUpdate = C_SignUpdate,
	.C_SignFinal = C_SignFinal,
	.C_SignRecoverInit = C_SignRecoverInit,
	.C_SignRecover = C_SignRecover,
	.C_VerifyInit = C_VerifyInit,
	.C_Verify = C_Verify,
	.C_VerifyUpdate = C_VerifyUpdate,
	.C_VerifyFinal = C_VerifyFinal,
	.C_VerifyRecoverInit = C_VerifyRecoverInit,
	.C_VerifyRecover = C_VerifyRecover,
	.C_DigestEncryptUpdate = C_DigestEncryptUpdate,
	.C_DecryptDigestUpdate = C_DecryptDigestUpdate,
	.C_SignEncryptUpdate = C_SignEncryptUpdate,
	.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
	.C_GenerateKey = C_GenerateKey,
	.C_GenerateKeyPair = C_GenerateKeyPair,
	.C_WrapKey = C_WrapKey,
	.C_UnwrapKey = C_UnwrapKey,
	.C_DeriveKey = C_DeriveKey,
	.C_SeedRandom = C_SeedRandom,
	.C_GenerateRandom = C_GenerateRandom,
	.C_GetFunctionStatus = C_GetFunctionStatus,
	.C_CancelFunction = C_CancelFunction,
	.C_WaitForSlotEvent = C_WaitForSlotEvent,
};

#if 0
static CK_INTERFACE interface_list[] = {
    {
        (CK_UTF8CHAR *)"PKCS 11",
        &pkcs11FunctionList,
        CKF_INTERFACE_FORK_SAFE /*XXX*/
    },
};
#endif

/**
 * \Brief Initializes Cryptoki library
 * \notes If pInitArgs is a non-NULL_PTR is must dereference to a CK_C_INITIALIZE_ARGS structure
 */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_init((CK_C_INITIALIZE_ARGS_PTR)pInitArgs));
}

/**
 * \brief Clean up miscellaneous Cryptoki-associated resources
 */
CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_deinit(pReserved));
}

/**
 * \breif Obtains general information about Cryptoki
 */
CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_get_lib_info(pInfo));
}

/**
 * \brief Obtains entry points of Cryptoki library functions
 */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    PKCS11_DEBUG("\r\n");
    if (!ppFunctionList)
    {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &pkcs11FunctionList;

    return CKR_OK;
}

#if 0
/**
 * \brief Obtains information about interface list
 */
CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfaceList, CK_ULONG_PTR pulCount)
{
    PKCS11_DEBUG("\r\n");

    CK_ULONG nmemb;
    CK_RV rv;
#if 0
    if (pulCount == NULL) {
        rv = CKR_ARGUMENTS_BAD;
        PKCS11_DEBUG("\r\n");
        goto ret;
    }
    PKCS11_DEBUG("\r\n");


    nmemb = sizeof(interface_list) / sizeof(interface_list[0]);

    if (pInterfaceList == NULL) {
        *pulCount = nmemb;
        rv = CKR_OK;
        goto ret;
    }
    PKCS11_DEBUG("\r\n");


    if (*pulCount < nmemb) {
        *pulCount = nmemb;
        rv = CKR_BUFFER_TOO_SMALL;
        goto ret;
    }
    PKCS11_DEBUG("\r\n");
#endif

   pInterfaceList = &interface_list[0];
   pulCount = sizeof(interface_list) / sizeof(interface_list[0]);
    //memcpy(pInterfaceList, interface_list, sizeof(interface_list));
    rv = CKR_OK;
    PKCS11_DEBUG("\r\n");

ret:
    return rv;
}

/**
 * \brief Obtains information about interface
 */
CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
		     CK_INTERFACE_PTR ppInterface, CK_FLAGS flags)
{
    PKCS11_DEBUG("\r\n");

    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}
#endif

/**
 * \brief Obtains a list of slots in the system
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_slot_get_list(tokenPresent, pSlotList, pulCount));
}

/**
 * \brief Obtains information about a particular slot
 */
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_slot_get_info(slotID, pInfo));
}

/**
 * \brief Obtains information about a particular token
 */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_token_get_info(slotID, pInfo));
}

/**
 * \brief Obtains a list of mechanisms supported by a token (in a slot)
 */
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_mech_get_list(slotID, pMechanismList, pulCount));
}

/**
 * \brief Obtains information about a particular mechanism of a token (in a slot)
 */
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs_mech_get_info(slotID, type, pInfo));
}

/**
 * \brief Initializes a token (in a slot)
 */
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_token_init(slotID, pPin, ulPinLen, pLabel));
}

/**
 * \brief Initializes the normal user's PIN
 */
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    ((void)hSession);
    ((void)pPin);
    ((void)ulPinLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Modifies the PIN of the current user
 */
CK_RV C_SetPIN
(
    CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR_PTR   pOldPin,
    CK_ULONG          ulOldLen,
    CK_UTF8CHAR_PTR   pNewPin,
    CK_ULONG          ulNewLen
)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Opens a connection between an application and a particular token or
 * sets up an application callback for token insertion
 */
CK_RV C_OpenSession
(
    CK_SLOT_ID            slotID,
    CK_FLAGS              flags,
    CK_VOID_PTR           pApplication,
    CK_NOTIFY             notify,
    CK_SESSION_HANDLE_PTR phSession
)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_session_open(slotID, flags, pApplication, notify, phSession));
}

/**
 * \brief Close the given session
 */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_session_close(hSession));
}

/**
 * \brief Close all open sessions
 */
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_session_closeall(slotID));
}

/**
 * \brief Retrieve information about the specified session
 */
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_session_get_info(hSession, pInfo));
}

/**
 * \brief Obtains the cryptographic operations state of a session
 */
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    ((void)hSession);
    ((void)pOperationState);
    ((void)pulOperationStateLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Sets the cryptographic operations state of a session
 */
CK_RV C_SetOperationState
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pOperationState,
    CK_ULONG          ulOperationStateLen,
    CK_OBJECT_HANDLE  hEncryptionKey,
    CK_OBJECT_HANDLE  hAuthenticationKey
)
{
    ((void)hSession);
    ((void)pOperationState);
    ((void)ulOperationStateLen);
    ((void)hEncryptionKey);
    ((void)hAuthenticationKey);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Login on the token in the specified session
 */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_session_login(hSession, userType, pPin, ulPinLen));
}

/**
 * \brief Log out of the token in the specified session
 */
CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Create a new object on the token in the specified session using the given attribute template
 */
CK_RV C_CreateObject
(
    CK_SESSION_HANDLE    hSession,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phObject
)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_object_create(hSession, pTemplate, ulCount, phObject));
}

/**
 * \brief Create a copy of the object with the specified handle
 */
CK_RV C_CopyObject
(
    CK_SESSION_HANDLE    hSession,
    CK_OBJECT_HANDLE     hObject,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject
)
{
    ((void)hSession);
    ((void)hObject);
    ((void)pTemplate);
    ((void)ulCount);
    ((void)phNewObject);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Destroy the specified object
 */
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_object_destroy(hSession, hObject));
}

/**
 * \brief Obtains the size of an object in bytes
 */
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_object_get_size(hSession, hObject, pulSize));
}

/**
 * \brief Obtains an attribute value of an object
 */
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_find_get_attribute(hSession, hObject, pTemplate, ulCount));
}

/**
 * \brief Change or set the value of the specified attributes on the specified object
 */
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    ((void)hSession);
    ((void)hObject);
    ((void)pTemplate);
    ((void)ulCount);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Initializes an object search in the specified session using the specified attribute template as search parameters
 */
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_find_init(hSession, pTemplate, ulCount));
}

/**
 * \brief Continue the search for objects in the specified session
 */
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_find_continue(hSession, phObject, ulMaxObjectCount, pulObjectCount));
}

/**
 * \brief Finishes an object search operation (and cleans up)
 */
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_find_finish(hSession));
}

/**
 * \brief Initializes an encryption operation using the specified mechanism and session
 */
CK_RV C_EncryptInit
(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR  pMechanism,
    CK_OBJECT_HANDLE  hObject
)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)hObject);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Perform a single operation encryption operation in the specified session
 */
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    ((void)hSession);
    ((void)pData);
    ((void)ulDataLen);
    ((void)pEncryptedData);
    ((void)pulEncryptedDataLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues a multiple-part encryption operation
 */
CK_RV C_EncryptUpdate
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pData,
    CK_ULONG          ulDataLen,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG_PTR      pulEncryptedDataLen
)
{
    ((void)hSession);
    ((void)pData);
    ((void)ulDataLen);
    ((void)pEncryptedData);
    ((void)pulEncryptedDataLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Finishes a multiple-part encryption operation
 */
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    ((void)hSession);
    ((void)pEncryptedData);
    ((void)pulEncryptedDataLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Initialize decryption using the specified object
 */
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)hObject);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Perform a single operation decryption in the given session
 */
CK_RV C_Decrypt
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG          ulEncryptedDataLen,
    CK_BYTE_PTR       pData,
    CK_ULONG_PTR      pulDataLen
)
{
    ((void)hSession);
    ((void)pEncryptedData);
    ((void)ulEncryptedDataLen);
    ((void)pData);
    ((void)pulDataLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues a multiple-part decryption operation
 */
CK_RV C_DecryptUpdate
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG          ulEncryptedDataLen,
    CK_BYTE_PTR       pData,
    CK_ULONG_PTR      pDataLen
)
{
    ((void)hSession);
    ((void)pEncryptedData);
    ((void)ulEncryptedDataLen);
    ((void)pData);
    ((void)pDataLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Finishes a multiple-part decryption operation
 */
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
    ((void)hSession);
    ((void)pData);
    ((void)pDataLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Initializes a message-digesting operation using the specified mechanism in the specified session
 */
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Digest the specified data in a one-pass operation and return the resulting digest
 */
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues a multiple-part digesting operation
 */
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Update a running digest operation by digesting a secret key with the specified handle
 */
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    ((void)hSession);
    ((void)hObject);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Finishes a multiple-part digesting operation
 */
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Initialize a signing operation using the specified key and mechanism
 */
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_signature_sign_init(hSession, pMechanism, hKey));
}

/**
 * \brief Sign the data in a single pass operation
 */
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_signature_sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen));
}

/**
 * \brief Continues a multiple-part signature operation
 */
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Finishes a multiple-part signature operation
 */
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Initializes a signature operation, where the data can be recovered from the signature
 */
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)hKey);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Signs single-part data, where the data can be recovered from the signature
 */
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    ((void)hSession);
    ((void)pData);
    ((void)ulDataLen);
    ((void)pSignature);
    ((void)pulSignatureLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Initializes a verification operation using the specified key and mechanism
 */
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Verifies a signature on single-part data
 */
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues a multiple-part verification operation
 */
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Finishes a multiple-part verification operation
 */
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Initializes a verification operation where the data is recovered from the signature
 */
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)hKey);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Verifies a signature on single-part data, where the data is recovered from the signature
 */
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    ((void)hSession);
    ((void)pSignature);
    ((void)ulSignatureLen);
    ((void)pData);
    ((void)pulDataLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues simultaneous multiple-part digesting and encryption operations
 */
CK_RV C_DigestEncryptUpdate
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pEncryptedPart,
    CK_ULONG_PTR      pulEncryptedPartLen
)
{
    ((void)hSession);
    ((void)pPart);
    ((void)ulPartLen);
    ((void)pEncryptedPart);
    ((void)pulEncryptedPartLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues simultaneous multiple-part decryption and digesting operations
 */
CK_RV C_DecryptDigestUpdate
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pDecryptedPart,
    CK_ULONG_PTR      pulDecryptedPartLen
)
{
    ((void)hSession);
    ((void)pPart);
    ((void)ulPartLen);
    ((void)pDecryptedPart);
    ((void)pulDecryptedPartLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues simultaneous multiple-part signature and encryption operations
 */
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    ((void)hSession);
    ((void)pPart);
    ((void)ulPartLen);
    ((void)pEncryptedPart);
    ((void)pulEncryptedPartLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Continues simultaneous multiple-part decryption and verification operations
 */
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    ((void)hSession);
    ((void)pEncryptedPart);
    ((void)ulEncryptedPartLen);
    ((void)pPart);
    ((void)pulPartLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Generates a secret key using the specified mechanism
 */
CK_RV C_GenerateKey
(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)pTemplate);
    ((void)ulCount);
    ((void)phKey);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Generates a public-key/private-key pair using the specified mechanism
 */
CK_RV C_GenerateKeyPair
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
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(qti_pkcs11_key_generate_pair(hSession, pMechanism, pPublicKeyTemplate,
                                                 ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey));
}

/**
 * \brief Wraps (encrypts) the specified key using the specified wrapping key and mechanism
 */
CK_RV C_WrapKey
(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR  pMechanism,
    CK_OBJECT_HANDLE  hWrappingKey,
    CK_OBJECT_HANDLE  hKey,
    CK_BYTE_PTR       pWrappedKey,
    CK_ULONG_PTR      pulWrappedKeyLen
)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)hWrappingKey);
    ((void)hKey);
    ((void)pWrappedKey);
    ((void)pulWrappedKeyLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Unwraps (decrypts) the specified key using the specified unwrapping key
 */
CK_RV C_UnwrapKey
(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_OBJECT_HANDLE     hUnwrappingKey,
    CK_BYTE_PTR          pWrappedKey,
    CK_ULONG             ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)hUnwrappingKey);
    ((void)pWrappedKey);
    ((void)ulWrappedKeyLen);
    ((void)pTemplate);
    ((void)ulCount);
    ((void)phKey);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Derive a key from the specified base key
 */
CK_RV C_DeriveKey
(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_OBJECT_HANDLE     hBaseKey,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    ((void)hSession);
    ((void)pMechanism);
    ((void)hBaseKey);
    ((void)pTemplate);
    ((void)ulCount);
    ((void)phKey);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Mixes in additional seed material to the random number generator
 */
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    ((void)hSession);
    ((void)pSeed);
    ((void)ulSeedLen);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_RANDOM_SEED_NOT_SUPPORTED);
}

/**
 * \brief Generate the specified amount of random data
 */
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * \brief Legacy function - see PKCS#11 v2.40
 */
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    ((void)hSession);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_PARALLEL);
}

/**
 * \brief Legacy function
 */
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    ((void)hSession);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_PARALLEL);
}

/**
 * \brief Wait for a slot event (token insertion, removal, etc) on the specified slot to occur
 */
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    ((void)flags);
    ((void)pSlot);
    ((void)pReserved);
    PKCS11_DEBUG("\r\n");
    PKCS11_DEBUG_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
}

