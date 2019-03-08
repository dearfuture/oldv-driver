#pragma once
#define _CRT_ALLOCATION_DEFINED
#ifdef __cplusplus
#ifndef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#endif
extern "C"
{
#pragma warning(push, 0)
#include <fltKernel.h>
#include <Wdmsec.h>
#include <windef.h>
#include <ntimage.h>
#include <stdarg.h>
#define NTSTRSAFE_LIB
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <intrin.h>
#include <Aux_klib.h>
#pragma warning(pop)
#define INOUT 
#ifdef ALLOC_PRAGMA
#define ALLOC_TEXT(Section, Name) __pragma(alloc_text(Section, Name))
#else
#define ALLOC_TEXT(Section, Name)
#endif
	// Returns true when it is running on the x64 system.
	inline bool IsX64() {
#ifdef _AMD64_
		return true;
#else
		return false;
#endif
	}
};
#else
#include <ntifs.h>
#include <WinDef.h>
#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include <ntddscsi.h>
#include <srb.h>
#include <ntimage.h>
#include <aux_klib.h>
#include <ntstrsafe.h>
#include "ddk_stdint.h"
#define INOUT 
#endif
#ifdef __cplusplus
#include "stdcpp.h"
#include "kernel_stl.h"
#include "unique_resource.h"
#include "scope_exit.h"
#endif

// Break point that works only when a debugger is attached.
#ifndef DBG_BREAK
#ifdef _ARM_
// Nullify it since an ARM device never allow us to attach a debugger.
#define DBG_BREAK()
#else
#define DBG_BREAK()               \
  if (KD_DEBUGGER_NOT_PRESENT) {  \
          } else {                        \
    __debugbreak();               \
          }                               \
  reinterpret_cast<void *>(0)
#endif
#endif
//
//#pragma comment(lib,"aux_klib.lib")
//#pragma comment(lib,"libcntpr.lib")
//#pragma comment(lib,"wdm.lib")
//#pragma comment(lib,"wdmsec.lib")
/*
libcntpr.lib
wdm.lib
wdmsec.lib
aux_klib.lib
*/

