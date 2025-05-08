/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * All rights reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef PKCS11_DEBUG_H_
#define PKCS11_DEBUG_H_

//#include "pkcs11_config.h"
//#define PKCS11_DEBUG_ENABLE

#ifdef PKCS11_DEBUG_ENABLE
const char * pkcs11_debug_get_ckr_name(CK_RV rv);
void qti_pkcs11_debug_attributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

#if defined(__linux__) || defined(__CYGWIN__)
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#define PKCS11_DEBUG_NOFILE(fmt, ...) { fflush(stdout); fprintf(stderr, "%d:%d:" fmt, getpid(), (int)syscall(SYS_gettid), ## __VA_ARGS__); fflush(stderr); }
#else
#define PKCS11_DEBUG_NOFILE(fmt, ...) { printf(fmt, ## __VA_ARGS__); }
#endif

#define PKCS11_DEBUG(fmt, ...)  PKCS11_DEBUG_NOFILE("%s:%d:" fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define PKCS11_DEBUG_RETURN(x)     { CK_RV __y = x; PKCS11_DEBUG("%s(%x)\n", pkcs11_debug_get_ckr_name(__y), (unsigned int)__y); return __y; }

#else
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
//#define PKCS11_DEBUG_NOFILE(...) { printf( ## __VA_ARGS__); }
//#define PKCS11_DEBUG(...) PKCS11_DEBUG_NOFILE("%s:%d:", __FUNCTION__, __LINE__, ## __VA_ARGS__)

#define PKCS11_DEBUG(...) printf("function %s line %d\n", __FUNCTION__, __LINE__);
#define PKCS11_DEBUG_RETURN(x)     { return x; }
#define qti_pkcs11_debug_attributes(x, y)

#endif


#endif /* PKCS11_DEBUG_H_ */
