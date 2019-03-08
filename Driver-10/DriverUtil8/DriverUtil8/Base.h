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
#define NTSTRSAFE_NO_CB_FUNCTIONS //全部使用CCH
#include <ntstrsafe.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <intrin.h>
#include <Aux_klib.h>
#include <wdmguid.h>
#pragma warning(pop)
};
//#else
//#include <ntifs.h>
//#include <WinDef.h>
//#include <stdarg.h>
//#include <stdio.h>
//#include <wchar.h>
//#include <ntddscsi.h>
//#include <srb.h>
//#include <ntimage.h>
//#include <aux_klib.h>
//#include <ntstrsafe.h>
//#include "ddk_stdint.h"
//#define INOUT 
#endif
#ifdef __cplusplus
#include "stdcpp.h"
#include "kernel_stl.h"
#include "unique_resource.h"
#include "scope_exit.h"
#include "Singleton.h"
#endif

#define INOUT 
#ifdef ALLOC_PRAGMA
#define ALLOC_TEXT(Section, Name) __pragma(alloc_text(Section, Name))
#else
#define ALLOC_TEXT(Section, Name)
#endif
// _countof. You do not want to type RTL_NUMBER_OF, do you?
#ifndef _countof
#define _countof(x)    RTL_NUMBER_OF(x)
#endif


// DbgPrintEx displays messages regardless of the filter settings
#ifndef DBG_PRINT
void write_log(char *format, ...);
#define DBG_PRINT(format, ...)  \
   write_log((format), __VA_ARGS__)
#endif

// Returns true when it is running on the x64 system.
inline bool IsX64() {
#ifdef _AMD64_
	return true;
#else
	return false;
#endif
}
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

//#ifndef PXI_SHIFT
//#define PXE_BASE          0xFFFFF6FB7DBED000UI64
//#define PXE_SELFMAP       0xFFFFF6FB7DBEDF68UI64
//#define PPE_BASE          0xFFFFF6FB7DA00000UI64
//#define PDE_BASE          0xFFFFF6FB40000000UI64
//#define PTE_BASE          0xFFFFF68000000000UI64
//
//#define PXE_TOP           0xFFFFF6FB7DBEDFFFUI64
//#define PPE_TOP           0xFFFFF6FB7DBFFFFFUI64
//#define PDE_TOP           0xFFFFF6FB7FFFFFFFUI64
//#define PTE_TOP           0xFFFFF6FFFFFFFFFFUI64
//
//#define PDE_KTBASE_AMD64  PPE_BASE
//
//#define PTI_SHIFT 12
//#define PDI_SHIFT 21
//#define PPI_SHIFT 30
//#define PXI_SHIFT 39
//
//#define PTE_PER_PAGE 512
//#define PDE_PER_PAGE 512
//#define PPE_PER_PAGE 512
//#define PXE_PER_PAGE 512
//
//#define PTI_MASK_AMD64 (PTE_PER_PAGE - 1)
//#define PDI_MASK_AMD64 (PDE_PER_PAGE - 1)
//#define PPI_MASK (PPE_PER_PAGE - 1)
//#define PXI_MASK (PXE_PER_PAGE - 1)
//#endif
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
Ntstrsafe.lib
*/
#define LOG_DEBUG(format, ...) \
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, (format), __VA_ARGS__)
#define LOG_INFO(format, ...) \
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, (format), __VA_ARGS__)
#define LOG_WARN(format, ...) \
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, (format), __VA_ARGS__)
#define LOG_ERROR(format, ...) \
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, (format), __VA_ARGS__)


#define LOG_DEBUG_SAFE(format, ...)   
#define LOG_INFO_SAFE(format, ...)                                         
#define LOG_WARN_SAFE(format, ...)                                         
#define LOG_ERROR_SAFE(format, ...)                                    


#pragma warning(disable:4018)
#pragma warning(disable:4242)

extern PDRIVER_OBJECT g_pDriverObject;
extern "C"
{
	DRIVER_INITIALIZE MainDriverEntry;
	DRIVER_UNLOAD UnLoad;
	DRIVER_INITIALIZE DriverEntry;
};

//0x80070000 
//#define STATUS_CUSTOM_STATUS(x) 0x80070000+x 不出错误框
//需要管理员处理才能工作 STATUS_DOWNGRADE_DETECTED
//恶意软件通报 STATUS_VIRUS_INFECTED