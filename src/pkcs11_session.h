/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef PKCS11_SESSION_H_
#define PKCS11_SESSION_H_

#include "cryptoki.h"
#include "pkcs11_init.h"
#include "pkcs11_object.h"

#define PKCS11_MAX_SESSIONS_ALLOWED 10

/** Session Context */
typedef struct _pkcs11_session_ctx
{
    CK_BBOOL            initialized;
    pkcs11_slot_ctx_ptr slot;
    CK_SESSION_HANDLE   handle;
    CK_STATE            state;
    CK_ULONG            error;
    CK_ATTRIBUTE_PTR    attrib_list;
    CK_ULONG            attrib_count;
    CK_ULONG            object_index;
    CK_ULONG            object_count;
    CK_OBJECT_HANDLE    active_object;
} pkcs11_session_ctx, *pkcs11_session_ctx_ptr;

CK_RV qti_pkcs11_session_check(pkcs11_session_ctx_ptr * pSession, CK_SESSION_HANDLE hSession);

CK_RV qti_pkcs11_session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
CK_RV qti_pkcs11_session_open(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession);
CK_RV qti_pkcs11_session_close(CK_SESSION_HANDLE hSession);
CK_RV qti_pkcs11_session_closeall(CK_SLOT_ID slotID);

#endif /* PKCS11_SESSION_H_ */
