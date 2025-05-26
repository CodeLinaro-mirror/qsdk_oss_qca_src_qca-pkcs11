/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef PKCS11_OBJECT_H_
#define PKCS11_OBJECT_H_

#include <stddef.h>
#include "cryptoki.h"

#define PKCS11_SEARCH_CACHE_SIZE        128
#define PKCS11_MAX_LABEL_SIZE           30
#define PKCS11_MAX_OBJECTS_ALLOWED      16

/** Populate an attribute based on the "object" */
typedef CK_RV (*attrib_f)(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute);

typedef struct _pkcs11_attrib_model
{
    const CK_ATTRIBUTE_TYPE type;
    const attrib_f          func;
} pkcs11_attrib_model, *pkcs11_attrib_model_ptr;

typedef struct _pkcs11_object
{

    /** The Class Identifier */
    CK_OBJECT_CLASS class_id;
    /** The Class Type */
    CK_ULONG class_type;
    /** List of attribute models this object possesses */
    pkcs11_attrib_model const * attributes;
    /** Count of attribute models */
    CK_ULONG     count;
    CK_ULONG     size;
    CK_VOID_PTR  config;
    CK_BYTE      slot;
    CK_FLAGS     flags;
    CK_UTF8CHAR  name[PKCS11_MAX_LABEL_SIZE + 1];
    void const * data;
} pkcs11_object, *pkcs11_object_ptr;

typedef struct _pkcs11_object_cache_t
{
    /** Arbitrary (but unique) non-null identifier for an object */
    CK_OBJECT_HANDLE handle;
    /** The actual object  */
    pkcs11_object_ptr object;
} pkcs11_object_cache_t;

extern pkcs11_object_cache_t pkcs11_object_cache[];

extern const pkcs11_attrib_model pkcs11_object_monotonic_attributes[];
extern const CK_ULONG pkcs11_object_monotonic_attributes_count;

#define PKCS11_OBJECT_FLAG_DESTROYABLE      0x01
#define PKCS11_OBJECT_FLAG_MODIFIABLE       0x02
#define PKCS11_OBJECT_FLAG_DYNAMIC          0x04

CK_RV qti_pkcs11_object_alloc(pkcs11_object_ptr * ppObject);
CK_RV qti_pkcs11_object_free(pkcs11_object_ptr pObject);
CK_RV qti_pkcs11_object_check(pkcs11_object_ptr * ppObject, CK_OBJECT_HANDLE handle);
CK_RV qti_pkcs11_object_find(pkcs11_object_ptr * ppObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV qti_pkcs11_object_get_class(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute);
CK_RV qti_pkcs11_object_get_name(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute);
CK_RV qti_pkcs11_object_get_type(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute);
CK_RV qti_pkcs11_object_get_destroyable(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute);
CK_RV qti_pkcs11_object_get_size(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
CK_RV qti_pkcs11_object_get_handle(pkcs11_object_ptr pObject, CK_OBJECT_HANDLE_PTR phObject);

CK_RV qti_pkcs11_object_create(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
CK_RV qti_pkcs11_object_destroy(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

CK_RV qti_pkcs11_object_deinit(pkcs11_lib_ctx_ptr pContext);

CK_RV qti_pkcs11_find_get_attribute(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV qti_pkcs11_find_init(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV qti_pkcs11_find_continue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
CK_RV qti_pkcs11_find_finish(CK_SESSION_HANDLE hSession);

CK_RV qti_pkcs11_init_check(pkcs11_lib_ctx_ptr * ppContext, CK_BBOOL lock);
CK_RV qti_pkcs11_config_load_objects(pkcs11_slot_ctx_ptr pSlot);
CK_RV qti_pkcs11_key_generate_pair (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
				    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
				    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
				    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
#endif /* PKCS11_OBJECT_H_ */
