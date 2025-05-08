/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <string.h>
#include "pkcs11_debug.h"
#include "pkcs11_init.h"
#include "pkcs11_mech.h"

/**
 * \defgroup pkcs11 Mechanisms (pkcs11_mech_)
   @{ */

typedef struct _pcks11_mech_table_e
{
    CK_MECHANISM_TYPE type;
    CK_MECHANISM_INFO info;
} pcks11_mech_table_e, *pcks11_mech_table_ptr;

#define PCKS11_MECH_ECC508_EC_CAPABILITY   (CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)

/* CK_MECHANISM_TYPE, MinKeySize, MaxKeySize, Flags */
static pcks11_mech_table_e pkcs11_mech_list_Trusted_app[] = {
    { CKM_EC_KEY_PAIR_GEN,{ 256, 256, CKF_HW | CKF_GENERATE | CKF_GENERATE_KEY_PAIR | PCKS11_MECH_ECC508_EC_CAPABILITY } },
    { CKM_ECDSA,{ 256, 256, CKF_HW | CKF_SIGN | CKF_VERIFY | PCKS11_MECH_ECC508_EC_CAPABILITY } },
};

#define TABLE_SIZE(x)   sizeof(x) / sizeof(x[0])

static CK_MECHANISM_INFO_PTR qti_pkcs11_mech_find_info(pcks11_mech_table_ptr pMechanismInfoList, CK_ULONG count, CK_MECHANISM_TYPE type)
{
    CK_MECHANISM_INFO_PTR rv = NULL_PTR;

    if (pMechanismInfoList)
    {
        CK_ULONG i;
        for (i = 0; i < count; i++)
        {
            if (type == pMechanismInfoList[i].type)
            {
                rv = &pMechanismInfoList[i].info;
                break;
            }
        }
    }
    return rv;
}

static void qti_pkcs11_mech_fill_list(CK_MECHANISM_TYPE_PTR pMechanismList, pcks11_mech_table_ptr pMechanismInfoList, CK_ULONG count)
{
    if (pMechanismList && pMechanismInfoList)
    {
        CK_ULONG i;
        for (i = 0; i < count; i++)
        {
            pMechanismList[i] = pMechanismInfoList[i].type;
        }
    }
}

CK_RV qti_pkcs11_mech_get_list(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    pkcs11_lib_ctx_ptr lib_ctx = qti_pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;
    pcks11_mech_table_ptr mech_list_ptr = NULL_PTR;
    CK_ULONG mech_cnt = 0;

    if (!lib_ctx)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    /* Ref PKCS11 Sec 5.5 - C_GetMechanismList */
    if (!pulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Retreive the slot context - i.e. the attached device (ECC508A, SHA256, etc) */
    slot_ctx = qti_pkcs11_slot_get_context(lib_ctx, slotID);

    if (!slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    mech_cnt = TABLE_SIZE(pkcs11_mech_list_Trusted_app);
    mech_list_ptr = pkcs11_mech_list_Trusted_app;

    /* Ref PKCS11 Sec 5.5 - C_GetMechanismList Requirement #2 */
    if (pMechanismList)
    {
        if (mech_cnt > *pulCount)
        {
            *pulCount = mech_cnt;
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            qti_pkcs11_mech_fill_list(pMechanismList, mech_list_ptr, mech_cnt);
        }
    }

    *pulCount = mech_cnt;

    return CKR_OK;
}

CK_RV qti_pkcs_mech_get_info(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;
    CK_MECHANISM_INFO_PTR mech_info_ptr = NULL_PTR;

    if (!lib_ctx || !lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!pInfo)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Retreive the slot context - i.e. the attached device (ECC508A, SHA256, etc) */
    slot_ctx = qti_pkcs11_slot_get_context(lib_ctx, slotID);

    if (!slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    mech_info_ptr = qti_pkcs11_mech_find_info(pkcs11_mech_list_Trusted_app, TABLE_SIZE(pkcs11_mech_list_Trusted_app), type);

    if (!mech_info_ptr)
    {
        return CKR_MECHANISM_INVALID;
    }

    memcpy(pInfo, mech_info_ptr, sizeof(CK_MECHANISM_INFO));

    return CKR_OK;
}

/** @} */

