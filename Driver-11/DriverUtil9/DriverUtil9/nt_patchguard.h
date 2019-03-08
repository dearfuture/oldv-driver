#pragma once
#include "Base.h"
#include "util_version.h"
#include "ntos.h"
#include "lock.h"
#include "WinX.h"
#include "nt_patchguard.h"
#include "fnparse.h"
#include "asm.h"
#include "mm_physical_scan.h"
#include "mm_independ_scan.h"
#include "PgContext.h"
VOID InitDisablePG();
EXTERN_C
void WinXpInstallPatchOnPatchGuardContext(
	__in PatchGuardContextInfo& Info);

namespace ddk
{
	static const ULONG DISPGP_MININUM_EPILOGUE_LENGTH = 12;
	static const ULONG DISPGP_MAXIMUM_EPILOGUE_LENGTH = 32;
	// Code taken from CmpAppendDllSection. Take long enough code to avoid false
	// positive.
	static const ULONG64 CmpAppendDllSection_PATTERN[] =
	{
		0x085131481131482E,
		0x1851314810513148,
		0x2851314820513148,
		0x3851314830513148,
		0x4851314840513148,
		0x5851314850513148,
		0x6851314860513148,
		0x7851314870513148,
		0x4800000080913148,
		0x3148000000889131,
		0x9131480000009091,
		0xA091314800000098,
		0x00A8913148000000,
		0x0000B09131480000,
		0x000000B891314800,
		0x31000000C0913148,
		0x8BD18B48C28B4811,
		0x843148000000C48A,
		0xC8D348000000C0CA,
	};
	// Just to know the length
	C_ASSERT(sizeof(CmpAppendDllSection_PATTERN) == 0x98);
#pragma LOCKEDCODE
	class nt_patchguard :public Singleton<nt_patchguard>
	{
	public:
		// A structure reflects inline hook code.
#include <pshpack1.h>
		//struct TrampolineCode {
		//	UCHAR jmp[6];
		//	FARPROC FunctionAddress;
		//};
		//static_assert(sizeof(TrampolineCode) == DISPGP_MININUM_EPILOGUE_LENGTH,
		//	"Size check");
		struct TrampolineCode {
			UCHAR jmp[2];
			FARPROC FunctionAddress;
			UCHAR code[2];
		};
		static_assert(sizeof(TrampolineCode) == DISPGP_MININUM_EPILOGUE_LENGTH,
			"Size check");
#include <poppack.h>

		// Holds a necessary context for installing and uninstalling inline hook.
		struct HookInfo {
			// A hook handler to be called instead
			FARPROC HookHandler;

			// An addresses to install inline hook
			UCHAR *HookAddresses[FNPARSEP_MAX_SUPPORTED_EPILOGUE_NUMBER];

			// A size of saved original code
			SIZE_T OriginalCodeSize;

			// A saved original code
			UCHAR OriginalCode[DISPGP_MAXIMUM_EPILOGUE_LENGTH];

			// Sizes in bytes to unwind to get return addresses from a stack pointers when
			// corresponding hook handlers are called.
			SIZE_T UnwindStackSize;
		};
		nt_patchguard() {
			install = false;
			RtlSecureZeroMemory(g_DispgpRegistryKey, sizeof(g_DispgpRegistryKey));

			g_ExAcquireResourceSharedLite = 0;
			g_HvcallInitiateHypercall = 0;
			g_KeDelayExecutionThread = 0;
			g_KeWaitForSingleObject = 0;
			g_KiScbQueueScanWorker = 0;
			g_KiSwInterruptDispatch = 0;
			g_KiCommitThreadWait = 0;
			g_MmNonPagedPoolStart = nullptr;
			g_PoolBigPageTable = nullptr;
			g_PoolBigPageTableSize = nullptr;
			g_PoolBigPageTableXp = nullptr;
			g_ApiSetpSearchForApiSetHost = 0;
			g_CcBcbProfiler = 0;
			g_DownLevelGetParentLanguageName = 0;
		}
		~nt_patchguard() {
			if (install)
			{
				/*KeDeregisterBugCheckCallback(&_KbugCheckCallBackRecord);
				KeDeregisterBugCheckReasonCallback(&_Kreason);*/
			}
		}
		void disable_pg_context()
		{
			WinXSymbols symbols = {};
			symbols.ExAcquireResourceSharedLite = g_ExAcquireResourceSharedLite;
			symbols.MmNonPagedPoolStart = g_MmNonPagedPoolStart;
			symbols.PoolBigPageTable = g_PoolBigPageTable;
			symbols.PoolBigPageTableSize = g_PoolBigPageTableSize;
			symbols.PoolBigPageTableXp = g_PoolBigPageTableXp;
			auto ns = WinXDisablePatchGuard(symbols);
			DBG_PRINT("pg status %x\r\n", ns);
		}
		bool disable_pg(PUNICODE_STRING RegPath)
		{
			RtlStringCchPrintfW(g_DispgpRegistryKey,
				RTL_NUMBER_OF(g_DispgpRegistryKey), L"%wZ",
				RegPath);
			if (install)
			{
				return true;
			}
			if (!loadSymbols())
			{
				DBG_PRINT("failed load symbols\r\n");
				return false;
			}
			//g_pDriverObject->DriverUnload = nullptr;
			DBG_PRINT("init patchguard disable\r\n");
			if (!ddk::util::IsWindows8OrGreater())
			{
				//不hook
				//InitDisablePG();
				disable_pg_context();
			}
			else
			{

				//Win8 Win8.1 Win10
				if (ddk::util::IsWindows10())
				{
					//投递dpc在每个cpu上进行搜索TIMER和WORKITEM
					
					//实际上hook 就解决了
					g_DispgpPatchGuardThreadRoutine = reinterpret_cast<UCHAR*>(g_HvcallInitiateHypercall);
					g_DispgpPatchGuardThreadRoutineEnd = g_DispgpPatchGuardThreadRoutine + PAGE_SIZE;

					g_DispgpSelfEncryptAndWaitRoutine = reinterpret_cast<UCHAR*>(g_KiSwInterruptDispatch);
					g_DispgpSelfEncryptAndWaitRoutineEnd = g_DispgpSelfEncryptAndWaitRoutine + PAGE_SIZE;

					g_DispgpPatchGuardStaticWorkItemRoutine = nullptr;
					win10_getStaticWorkItem();

				}
				if (ddk::util::IsWindows80())
				{
					g_DispgpPatchGuardStaticWorkItemRoutine = g_DispgpSelfEncryptAndWaitRoutine = g_DispgpPatchGuardStaticWorkItemRoutine
						= g_DispgpPatchGuardThreadRoutineEnd = g_DispgpSelfEncryptAndWaitRoutineEnd = nullptr;
					//Win8上比较难以定位的是ThreadRoutine
					g_DispgpPatchGuardStaticWorkItemRoutine = reinterpret_cast<UCHAR *>(g_KiScbQueueScanWorker);
					g_DispgpSelfEncryptAndWaitRoutine = g_DispgpPatchGuardStaticWorkItemRoutine;
					g_DispgpSelfEncryptAndWaitRoutineEnd = g_DispgpPatchGuardThreadRoutine + PAGE_SIZE;
					g_DispgpPatchGuardThreadRoutine = reinterpret_cast<UCHAR*>(g_DownLevelGetParentLanguageName);
					g_DispgpPatchGuardThreadRoutineEnd = g_DispgpPatchGuardThreadRoutine + PAGE_SIZE;

					/*g_MmNonPagedPoolStart = new ULONG_PTR;
					*g_MmNonPagedPoolStart=0xFFFFE00000000000UI64;*/
				}
				if (ddk::util::IsWindows81())
				{
					win81_InitializeSelfEncryptAndWaitRoutineRange();
					win81_InitializePatchGuardThreadRoutineRange();
				}
				//四个hook的初始化
				if (1)
				{
					// Initialization for DequeuingWorkItemRoutine
					const auto pDequeueRoutine = reinterpret_cast<UCHAR*>(g_KiCommitThreadWait);
					auto status = DispgpSetEpilogueHookInfo(
						pDequeueRoutine,
						reinterpret_cast<FARPROC>(AsmDequeuingWorkItemRoutineHookHandler),
						&g_DispgpDequeueRoutineHookInfo);
					if (!NT_SUCCESS(status)) {
						DBG_PRINT("KiCommitThreadWait failed\r\n");
						return false;
					}
					status = DispgpFixupHookHandler(g_DispgpDequeueRoutineHookInfo);
					if (!NT_SUCCESS(status)) {
						return false;
					}
					const auto pKeWaitForSingleObject = reinterpret_cast<UCHAR*>(g_KeWaitForSingleObject);
					// Initialization for WaitRoutines
					status = DispgpSetEpilogueHookInfo(
						pKeWaitForSingleObject,
						reinterpret_cast<FARPROC>(AsmKeWaitForSingleObjectHookHandler),
						&g_DispgpKeWaitForSingleObjectHookInfo);
					if (!NT_SUCCESS(status)) {
						DBG_PRINT("KeWaitForSingleObject failed\r\n");
						return false;
					}
					status = DispgpFixupHookHandler(g_DispgpKeWaitForSingleObjectHookInfo);
					if (!NT_SUCCESS(status)) {
						return false;
					}
					const auto pKeDelayExecutionThread = reinterpret_cast<UCHAR*>(g_KeDelayExecutionThread);
					status = DispgpSetEpilogueHookInfo(
						pKeDelayExecutionThread,
						reinterpret_cast<FARPROC>(AsmKeDelayExecutionThreadHookHandler),
						&g_DispgpKeDelayExecutionThreadHookInfo);
					if (!NT_SUCCESS(status)) {
						DBG_PRINT("KeDelayExecutionThread failed\r\n");
						return false;
					}
					status = DispgpFixupHookHandler(g_DispgpKeDelayExecutionThreadHookInfo);
					if (!NT_SUCCESS(status)) {
						return false;
					}

					// Initialization for TinyPatchGuardDpcRoutine
					const auto TinyPatchGuardDpcRoutine = reinterpret_cast<UCHAR*>(g_CcBcbProfiler);
					status = DispgpSetPrologueHookInfo(
						TinyPatchGuardDpcRoutine,
						reinterpret_cast<FARPROC>(ddk::nt_patchguard::DispgpTinyPatchGuardDpcRoutineHookHandler),
						&g_DispgpTinyPatchGuardDpcRoutineHookInfo);
				}
				if (1)
				{
					cpu_lock lock;
					lock.lock();
					auto old = KeRaiseIrqlToDpcLevel();
					auto exit_ = std::experimental::make_scope_exit([&]() {KeLowerIrql(old); lock.unlock(); });
					//if (!ddk::util::IsWindows10())
					{
						auto status = DispgpHookDequeuingWorkItemRoutine();
						if (!NT_SUCCESS(status)) {
							return false;
						}

					}
					auto status = DispgpHookWaitRoutines();
					if (!NT_SUCCESS(status)) {
						return false;
					}

					status = DispgpHookTinyPatchGuardDpcRoutine();
					if (!NT_SUCCESS(status)) {
						return false;
					}
				}
			}
			install = true;
			return true;
		}
		static void
			DispgpTinyPatchGuardDpcRoutineHookHandler(
				PKDPC Dpc, 
				PVOID DeferredContext,
				PVOID SystemArgument1,
				PVOID SystemArgument2) {
			UNREFERENCED_PARAMETER(Dpc);
			UNREFERENCED_PARAMETER(DeferredContext);
			UNREFERENCED_PARAMETER(SystemArgument1);
			UNREFERENCED_PARAMETER(SystemArgument2);

			LOG_INFO_SAFE("TinyPatchGuardDpcRoutine detected.");
		}
		bool DispgpIsReturnningToPatchGuard(
			ULONG_PTR ReturnAddress) {
			PAGED_CODE();

			// It should be a kernel thread because it is executed by either
			// ExpWorkerThread() or a thread created by PsCreateSystemThread().
			if (PsGetProcessId(PsGetCurrentProcess()) != reinterpret_cast<HANDLE>(4)) {
				return false;
			}

			auto returnAddress = reinterpret_cast<UCHAR *>(ReturnAddress);

			// Is it inside of PatchGuardThreadRoutine?
			if (g_DispgpPatchGuardThreadRoutine <= returnAddress &&
				returnAddress <= g_DispgpPatchGuardThreadRoutineEnd) {
				LOG_DEBUG_SAFE("Inside of PatchGuardThreadRoutine");
				return true;
			}

			// Is it inside of SelfEncryptAndWaitRoutine?
			if (g_DispgpSelfEncryptAndWaitRoutine <= returnAddress &&
				returnAddress <= g_DispgpSelfEncryptAndWaitRoutineEnd) {
				LOG_DEBUG_SAFE("Inside of SelfEncryptAndWaitRoutine");
				return true;
			}

			// Is it outside of any of image files?
			void *base = nullptr;
			if (!RtlPcToFileHeader(returnAddress, &base)) {
				LOG_DEBUG_SAFE("Outside of image files");
				return true;
			}

			return false;
		}
	private:
		nt_lock _lock;
		KBUGCHECK_CALLBACK_RECORD _KbugCheckCallBackRecord;
		KBUGCHECK_REASON_CALLBACK_RECORD _Kreason;
		bool install;
		bool can_write;
		wchar_t g_DispgpRegistryKey[200];
		// always
		ULONG_PTR g_ExAcquireResourceSharedLite;
		// ifVistaOr7
		POOL_TRACKER_BIG_PAGES** g_PoolBigPageTable;
		// ifXp
		POOL_TRACKER_BIG_PAGES_XP** g_PoolBigPageTableXp;
		// ifNot8OrGreater
		SIZE_T* g_PoolBigPageTableSize;
		ULONG_PTR* g_MmNonPagedPoolStart;
		// if8OrGreater
		ULONG_PTR g_KiScbQueueScanWorker;//Win10上这个0
		ULONG_PTR g_KiCommitThreadWait;
		ULONG_PTR g_KeDelayExecutionThread;
		ULONG_PTR g_KeWaitForSingleObject;
		ULONG_PTR g_HvcallInitiateHypercall;
		ULONG_PTR g_KiSwInterruptDispatch;
		ULONG_PTR g_ApiSetpSearchForApiSetHost;//Win10上这个0
		ULONG_PTR g_CcBcbProfiler;
		ULONG_PTR g_DownLevelGetParentLanguageName;
	private:
		ULONG_PTR g_KiWaitAlways;
		ULONG_PTR g_KiWaitNever;
		ULONG_PTR g_KiBalanceSetManagerPeriodicDpc;
	public:
		UCHAR *g_DispgpPatchGuardThreadRoutine;
		UCHAR *g_DispgpPatchGuardThreadRoutineEnd;
		UCHAR *g_DispgpSelfEncryptAndWaitRoutine;
		UCHAR *g_DispgpSelfEncryptAndWaitRoutineEnd;
		UCHAR *g_DispgpPatchGuardStaticWorkItemRoutine;
	private:
		HookInfo g_DispgpDequeueRoutineHookInfo;
		HookInfo g_DispgpKeWaitForSingleObjectHookInfo;
		HookInfo g_DispgpKeDelayExecutionThreadHookInfo;
		HookInfo g_DispgpTinyPatchGuardDpcRoutineHookInfo;
	private:
		struct SymbolSet
		{
			const wchar_t* SymbolName;
			void** Variable;
			bool(*IsRequired)();
		};
		bool loadSymbols()
		{
			const auto always = []() { return true; };
			const auto if8OrGreater = []() { return ddk::util::IsWindows8OrGreater(); };
			const auto ifNot8OrGreater = []() { return !ddk::util::IsWindows8OrGreater(); };
			const auto ifVistaOr7 = []()
			{
				return ddk::util::IsWindows7orVista();
			};
			const auto ifXpOrVista = []()
			{
				return ddk::util::IsWindowsXpOrVista();
			};
			const auto ifXp = []() { return ddk::util::IsWindowsXp(); };
			const auto if10 = []() { return ddk::util::IsWindows10(); };
			const auto if8And81 = []() {return ddk::util::IsWindows8OrGreater() && (!ddk::util::IsWindows10()); };
			const auto if80 = []() {return ddk::util::IsWindows80(); };
			const SymbolSet requireSymbols[] =
			{
				{ L"ntoskrnl!ExAcquireResourceSharedLite",  reinterpret_cast<void**>(&g_ExAcquireResourceSharedLite),   always, },
				{ L"ntoskrnl!PoolBigPageTable",             reinterpret_cast<void**>(&g_PoolBigPageTable),              always, },
				{ L"ntoskrnl!PoolBigPageTable",             reinterpret_cast<void**>(&g_PoolBigPageTableXp),            ifXp, },
				{ L"ntoskrnl!PoolBigPageTableSize",         reinterpret_cast<void**>(&g_PoolBigPageTableSize),          always, },
				{ L"ntoskrnl!MmNonPagedPoolStart",          reinterpret_cast<void**>(&g_MmNonPagedPoolStart),           ifNot8OrGreater, },
				{ L"ntoskrnl!KiScbQueueScanWorker",         reinterpret_cast<void**>(&g_KiScbQueueScanWorker),          if8And81, },
				{ L"ntoskrnl!KiCommitThreadWait",           reinterpret_cast<void**>(&g_KiCommitThreadWait),            if8OrGreater, },
				{ L"ntoskrnl!DownLevelGetParentLanguageName",   reinterpret_cast<void**>(&g_DownLevelGetParentLanguageName),	if80, },
				{ L"ntoskrnl!KeDelayExecutionThread",       reinterpret_cast<void**>(&g_KeDelayExecutionThread),        if8OrGreater, },
				{ L"ntoskrnl!KeWaitForSingleObject",        reinterpret_cast<void**>(&g_KeWaitForSingleObject),         if8OrGreater, },
				{ L"ntoskrnl!ApiSetpSearchForApiSetHost",   reinterpret_cast<void**>(&g_ApiSetpSearchForApiSetHost),	if8And81, },
				{ L"ntoskrnl!CcBcbProfiler",				reinterpret_cast<void**>(&g_CcBcbProfiler),					if8OrGreater, },
				{ L"ntoskrnl!HvcallInitiateHypercall",      reinterpret_cast<void**>(&g_HvcallInitiateHypercall),       if10, },
				{ L"ntoskrnl!KiSwInterruptDispatch",		reinterpret_cast<void**>(&g_KiSwInterruptDispatch),         if10, },
				{ L"ntoskrnl!KiWaitNever",					reinterpret_cast<void**>(&g_KiWaitNever),					if10, },
				{ L"ntoskrnl!KiWaitAlways",					reinterpret_cast<void**>(&g_KiWaitAlways),					if10, },
				{ L"ntoskrnl!KiBalanceSetManagerPeriodicDpc",	reinterpret_cast<void**>(&g_KiBalanceSetManagerPeriodicDpc),	if10, },
			};
			for (const auto& request : requireSymbols)
			{
				if (!request.IsRequired())
				{
					continue;
				}
				auto status = ddk::util::UtilLoadPointerVaule(g_DispgpRegistryKey,
					request.SymbolName, request.Variable);
				if (!NT_SUCCESS(status))
				{
					DBG_PRINT("Symbol LoaderX %ws was not found.\r\n", request.SymbolName);
					return false;
				}
				DBG_PRINT("find %ws %p\r\n", request.SymbolName, (*request.Variable));
			}
			DBG_PRINT("SymLoad End\r\n");
			// Check if the symbol address is correct by comparing with the real value
			UNICODE_STRING procName =
				RTL_CONSTANT_STRING(L"ExAcquireResourceSharedLite");
			const auto realAddress =
				reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&procName));
			if (realAddress != g_ExAcquireResourceSharedLite)
			{
				DBG_PRINT("Symbol information is not fresh.\n");
				return false;
			}
			return true;
		}
		void win10_getStaticWorkItem()
		{
			g_DispgpPatchGuardStaticWorkItemRoutine = nullptr;
			g_DispgpPatchGuardStaticWorkItemRoutine = reinterpret_cast<UCHAR*>(g_KiSwInterruptDispatch-0x18);	
		}
		void win81_InitializePatchGuardThreadRoutineRange()
		{
			g_DispgpPatchGuardThreadRoutine = g_DispgpPatchGuardThreadRoutineEnd = nullptr;

			auto HintFunctionAddress = reinterpret_cast<UCHAR*>(g_ApiSetpSearchForApiSetHost);
			UCHAR *pPatchGuardThreadRoutine = nullptr;
		
				UCHAR *base = nullptr;
				auto entry = FnparseLookupFunctionEntry(ddk::mem_util::UtilDataToFp(HintFunctionAddress),
					reinterpret_cast<void **>(&base));
				if (!entry) {
					return ;
				}
				entry++;  // Next entry
				pPatchGuardThreadRoutine =
					reinterpret_cast<UCHAR *>(entry->BeginAddress + base);
			
			// Get a length of the function
			const auto length = FnparseGetFunctionLength(pPatchGuardThreadRoutine);
			DBG_PRINT("Routine= %p, Length= %d", pPatchGuardThreadRoutine, length);
			if (!length) {
				return ;
			}

			g_DispgpPatchGuardThreadRoutine = pPatchGuardThreadRoutine;
			g_DispgpPatchGuardThreadRoutineEnd = pPatchGuardThreadRoutine + length;
			DBG_PRINT("PatchGuardThreadRoutine %p - %p",
				g_DispgpPatchGuardThreadRoutine,
				g_DispgpPatchGuardThreadRoutineEnd);
			return ;
		}
		void win81_InitializeSelfEncryptAndWaitRoutineRange()
		{
			g_DispgpSelfEncryptAndWaitRoutine = g_DispgpPatchGuardThreadRoutineEnd = nullptr;
			g_DispgpPatchGuardStaticWorkItemRoutine = nullptr;
			auto HintFunctionAddress = reinterpret_cast<UCHAR *>(g_KiScbQueueScanWorker);
			g_DispgpPatchGuardStaticWorkItemRoutine = HintFunctionAddress;
			UCHAR *base = nullptr;
			auto entry = FnparseLookupFunctionEntry(ddk::mem_util::UtilDataToFp(HintFunctionAddress),
				reinterpret_cast<void **>(&base));
			if (!entry) {
				return ;
			}
			entry++;  // Next entry
			auto pSelfEncryptAndWaitRoutine =
				reinterpret_cast<UCHAR *>(entry->BeginAddress + base);

			// Get a length of the function
			const auto length = FnparseGetFunctionLength(pSelfEncryptAndWaitRoutine);
			DBG_PRINT("Routine= %p, Length= %d", pSelfEncryptAndWaitRoutine, length);
			if (!length) {
				return ;
			}

			g_DispgpSelfEncryptAndWaitRoutine = pSelfEncryptAndWaitRoutine;
			g_DispgpSelfEncryptAndWaitRoutineEnd = pSelfEncryptAndWaitRoutine + length;
			DBG_PRINT("DispgpSelfEncryptAndWaitRoutine %p - %p",
				g_DispgpSelfEncryptAndWaitRoutine,
				g_DispgpSelfEncryptAndWaitRoutineEnd);
			return ;
		}
		private:
			NTSTATUS DispgpSetEpilogueHookInfo(
				UCHAR *FunctionAddress, FARPROC HookHandler, HookInfo *Info) 
			{
				NT_ASSERT(FunctionAddress);
				NT_ASSERT(HookHandler);
				NT_ASSERT(Info);

				// Get a length and an address of the beginning of epilogue
				auto epilogueInfo = FnparseGetEpilogueInfo(FunctionAddress);
				if (!epilogueInfo.EpilogueLength) {
					DBG_PRINT("failed FnparseGetEpilogueInfo1\r\n");
					return STATUS_UNSUCCESSFUL;
				}

				if (epilogueInfo.EpilogueLength < DISPGP_MININUM_EPILOGUE_LENGTH ||
					epilogueInfo.EpilogueLength > DISPGP_MAXIMUM_EPILOGUE_LENGTH) {
					DBG_PRINT("failed FnparseGetEpilogueInfo2 %d\r\n",epilogueInfo.EpilogueLength);
					DBG_PRINT("failed %p\r\n", epilogueInfo.EpilogueAddresses[0]);
					return STATUS_UNSUCCESSFUL;
				}

				// Only supports the exactly the same epilogue
				for (auto &epilogueAddress : epilogueInfo.EpilogueAddresses) {
					if (!epilogueAddress) {
						break;
					}
					if (memcmp(epilogueInfo.EpilogueAddresses[0], epilogueAddress,
						epilogueInfo.EpilogueLength) != 0) {
						DBG_PRINT("Unmatched epilogue code %p and %p\r\n",
							epilogueInfo.EpilogueAddresses[0], epilogueAddress);
						return STATUS_UNSUCCESSFUL;
					}
				}

				// Save information
				// It is safe to use the same length and original code as we have made sure
				// that all epilogues have the same code above
				Info->HookHandler = HookHandler;
				memcpy(Info->HookAddresses, epilogueInfo.EpilogueAddresses,
					sizeof(epilogueInfo.EpilogueAddresses));
				static_assert(
					sizeof(Info->HookAddresses) == sizeof(epilogueInfo.EpilogueAddresses),
					"Size check");
				Info->OriginalCodeSize = epilogueInfo.EpilogueLength;
				memcpy(Info->OriginalCode, Info->HookAddresses[0], Info->OriginalCodeSize);
				Info->UnwindStackSize = epilogueInfo.UnwindStackSize;
				return STATUS_SUCCESS;
			}

			// Copy saved original code into a hook handler.
			NTSTATUS DispgpFixupHookHandler(
					const HookInfo &Info) 
			{

#ifdef _AMD64_
				// Locates where to copy original code, which is allocated by a NOP_32
				// macro.
				static const UCHAR NOP4[] = {
					0x90, 0x90, 0x90, 0x90,
				};
				auto fixupAddress = ddk::mem_util::MmMemMem(Info.HookHandler, 32, NOP4, sizeof(NOP4));
				if (!fixupAddress) {
					DBG_PRINT("failed to find fixupAddress\r\n");
					return STATUS_UNSUCCESSFUL;
				}

				// Copy epilogue.
				auto status = ddk::mem_util::MmForceMemCpy(
					fixupAddress, Info.OriginalCode, Info.OriginalCodeSize);
				if (!NT_SUCCESS(status)) {
					DBG_PRINT("failed to copy mem\r\n");
					return status;
				}
				ddk::mem_util::MmInvalidateInstructionCache(fixupAddress, Info.OriginalCodeSize);
#endif
				return STATUS_SUCCESS;
			}
			NTSTATUS DispgpSetPrologueHookInfo(
				UCHAR *FunctionAddress, FARPROC HookHandler, HookInfo *Info) {
				PAGED_CODE();
				NT_ASSERT(FunctionAddress);
				NT_ASSERT(HookHandler);
				NT_ASSERT(Info);

				// Has one hook address as it is a prologue hook
				Info->HookHandler = HookHandler;
				Info->HookAddresses[0] = FunctionAddress;
				Info->OriginalCodeSize = DISPGP_MININUM_EPILOGUE_LENGTH;
				memcpy(Info->OriginalCode, Info->HookAddresses[0], Info->OriginalCodeSize);

				DBG_PRINT("HookHandler= %p, HookAddress= %p, OriginalCodeSize= %d",
					Info->HookHandler, Info->HookAddresses[0], Info->OriginalCodeSize);

				return STATUS_SUCCESS;
			}
			NTSTATUS DispgpInstallHook(
				const HookInfo &Info) {
				auto status = STATUS_UNSUCCESSFUL;
				for (auto hookAddress : Info.HookAddresses) {
					if (!hookAddress) {
						break;
					}
					DBG_PRINT("Installing a hook %p => %p", hookAddress, Info.HookHandler);
					auto newCode = DispgpMakeTrampolineCode(hookAddress, Info.HookHandler);
					status = ddk::mem_util::MmForceMemCpy(hookAddress, newCode.jmp, sizeof(newCode));
					ddk::mem_util::MmInvalidateInstructionCache(hookAddress, sizeof(newCode));
					if (!NT_SUCCESS(status)) {
						DBG_PRINT("failed copy memory %x\r\n", status);
						break;
					}
				}
				return status;
			}
			TrampolineCode DispgpMakeTrampolineCode(
				UCHAR *HookAddress, FARPROC HookHandler) 
			{
#ifdef _AMD64_

				//          jmp qword ptr [nextline]
				// nextline:
				//          dq HookHandler
				UNREFERENCED_PARAMETER(HookAddress);
				/*return{
					{
						0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
					},
					HookHandler,
				};*/
				//mov rbx,handler
				//jmp rbx
				return{
					{
						0x48, 0xbb,
					},
					HookHandler,
					{
						0xFF, 0xe3,
					},
				};
#endif
			}
		private:
			NTSTATUS DispgpHookWaitRoutines() {
				DBG_PRINT("Hooking WaitRoutines...");

				auto status = DispgpInstallHook(g_DispgpKeWaitForSingleObjectHookInfo);
				if (!NT_SUCCESS(status)) {
					return status;
				}

				status = DispgpInstallHook(g_DispgpKeDelayExecutionThreadHookInfo);
				return status;
			}
			NTSTATUS
				DispgpHookDequeuingWorkItemRoutine() {
				DBG_PRINT("Hooking DequeuingWorkItemRoutine...");
				return DispgpInstallHook(g_DispgpDequeueRoutineHookInfo);
			}
			NTSTATUS
				DispgpHookTinyPatchGuardDpcRoutine() {
				DBG_PRINT("Hooking TinyPatchGuardDpcRoutine...");
				return DispgpInstallHook(g_DispgpTinyPatchGuardDpcRoutineHookInfo);
			}
		private:
			void DispgpWaitRoutinesHookHandler(
				ULONG_PTR *AddressOfReturnAddress) {
				// It should be PASSIVE_LEVEL because it should be called from epilogue of
				// functions that are supposed to be called in PASSIVE_LEVEL.
				if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
					return;
				}
				if (g_DispgpPatchGuardStaticWorkItemRoutine==nullptr)
				{

				}
				// Check its return address.
				const auto returnAddress = *AddressOfReturnAddress;
				if (!DispgpIsReturnningToPatchGuard(returnAddress)) {
					return;
				}

				LOG_DEBUG_SAFE("StackPointer = %p", AddressOfReturnAddress);
				LOG_INFO_SAFE("PatchGuard detected (returning to %p).", returnAddress);

#ifdef _AMD64_
				//
				// It seems that Windows on x64 does not like to call synchronization APIs
				// from here unlike ARM's kernel. The author could not figure out exactly
				// what it was wrong, but these were things did not work:
				//  - calling the API from here
				//  - calling the API via the other function call like DispgWaitForever()
				//  - calling the API with a jmp instruction at the return address
				//
				// Thus, it calls the API via a call instruction at the return address.
				//
				*AddressOfReturnAddress = reinterpret_cast<ULONG_PTR>(AsmWaitForever);
#endif
			}
		public:
			// A structure used for an argument of the PatchGuardStaticWorkItem routine.
			struct PatchGuardStaticWorkItemContext {
				ULONG_PTR EncodedWorkItemRoutine;
				ULONG_PTR EncodedWorkItemContext;
				ULONG_PTR XorKey;
			};

			// A basic PatchGuard context definition for validation.
			struct PatchGuardContext {
				UCHAR Reserved[0xc8];
				FARPROC ExAcquireResourceSharedLite;
				FARPROC ExAcquireResourceSharedLite2;
			};
			static_assert(sizeof(PatchGuardContext) == 0xc8 + sizeof(void *)*2, "Size check");
			struct PatchGuardContext10 {
				UCHAR Reserved[0xD0];
				FARPROC ExAcquireResourceSharedLite;
			};
			static_assert(sizeof(PatchGuardContext10) == 0xd0 + sizeof(void *), "Size check");
			void handler_KeWaitForSingleObject(ULONG_PTR StackPointer)
			{
				auto addressOfReturnAddress = reinterpret_cast<ULONG_PTR *>(
					StackPointer + g_DispgpKeWaitForSingleObjectHookInfo.UnwindStackSize);
				DispgpWaitRoutinesHookHandler(addressOfReturnAddress);
			}
			void handler_KeDelayExecutionThread(ULONG_PTR StackPointer)
			{
				auto addressOfReturnAddress = reinterpret_cast<ULONG_PTR *>(
					StackPointer + g_DispgpKeDelayExecutionThreadHookInfo.UnwindStackSize);
				DispgpWaitRoutinesHookHandler(addressOfReturnAddress);
			}
			bool IsPgWorkItem10(const WORK_QUEUE_ITEM *WorkItem)
			{
				UCHAR *base = nullptr;
				RtlPcToFileHeader(WorkItem->WorkerRoutine, reinterpret_cast<void **>(&base));
				LOG_DEBUG_SAFE("WorkRoutine = %p, Parameter = %p, Base = %p, Offset = %p",
					WorkItem->WorkerRoutine, WorkItem->Parameter, base,
					reinterpret_cast<UCHAR *>(WorkItem->WorkerRoutine) - base);

				PatchGuardContext10 *pgContext = nullptr;
				if (base) {
					// If it is inside of image, we need to check whether it is inside of
					// PatchGuardStaticWorkItemRoutine.
					if (reinterpret_cast<UCHAR *>(WorkItem->WorkerRoutine) !=
						g_DispgpPatchGuardStaticWorkItemRoutine) {
						// If it is not neither, it is not PatchGuard's work item routine.
						return false;
					}

					// If it is, it is probably PatchGuard's one. If so, try to decrypt it
					// as it should be encrypted.
					LOG_DEBUG_SAFE("Calling PatchGuardStaticWorkItemRoutine %p",
						WorkItem->WorkerRoutine);
					const auto context = reinterpret_cast<PatchGuardStaticWorkItemContext *>(
						WorkItem->Parameter);
					pgContext = reinterpret_cast<PatchGuardContext10 *>(
						context->EncodedWorkItemContext ^ context->XorKey);
				}
				else {
					// If it is not, it is probably PatchGuard's one.
					LOG_DEBUG_SAFE("Calling a non-image region %p", WorkItem->WorkerRoutine);
					pgContext = reinterpret_cast<PatchGuardContext10 *>(WorkItem->Parameter);
					return true;
				}

				// Determine whether it has a pointer to ExAcquireResourceSharedLite() at
				// a specific offset.
				if (!ddk::mem_util::MmIsAccessibleAddress(&pgContext->ExAcquireResourceSharedLite)) {
					return false;
				}
				return (g_ExAcquireResourceSharedLite == reinterpret_cast<ULONG_PTR>(pgContext->ExAcquireResourceSharedLite));
			}
			bool IsPatchGuardWorkItem(
				const WORK_QUEUE_ITEM *WorkItem) {
				PAGED_CODE();

				// The thread should be a kernel thread because this function is intended
				// to handle a call from ExpWorkerThread().
				if (PsGetProcessId(PsGetCurrentProcess()) != reinterpret_cast<HANDLE>(4)) {
					return false;
				}
				if (ddk::util::IsWindows10())
				{
					if (!MmIsAddressValid(PVOID(WorkItem)))
					{
						return false;
					}
					//if (!MmIsNonPagedSystemAddressValid(PVOID(WorkItem)))
					//{
					//	return false;
					//}
					if (!MmIsAddressValid(PVOID(WorkItem->WorkerRoutine)))
					{
						return false;
					}
					if (!MmIsAddressValid(PVOID(WorkItem->Parameter)))
					{
						return false;
					}
				}
				// Work item's addresses should be in a kernel memory and accessible.
				if (WorkItem < MmSystemRangeStart || !ddk::mem_util::MmIsAccessibleAddress(WorkItem)) {
					return false;
				}
				if (WorkItem->WorkerRoutine < MmSystemRangeStart ||
					!ddk::mem_util::MmIsExecutableAddress(WorkItem->WorkerRoutine)) {
					return false;
				}
				if (WorkItem->Parameter < MmSystemRangeStart ||
					!ddk::mem_util::MmIsAccessibleAddress(WorkItem->Parameter)) {
					return false;
				}

				// Determine if it is inside of any image.
				UCHAR *base = nullptr;
				RtlPcToFileHeader(WorkItem->WorkerRoutine, reinterpret_cast<void **>(&base));
				LOG_DEBUG_SAFE("WorkRoutine = %p, Parameter = %p, Base = %p, Offset = %p",
					WorkItem->WorkerRoutine, WorkItem->Parameter, base,
					reinterpret_cast<UCHAR *>(WorkItem->WorkerRoutine) - base);

				PatchGuardContext *pgContext = nullptr;
				if (base) {
					// If it is inside of image, we need to check whether it is inside of
					// PatchGuardStaticWorkItemRoutine.
					if (reinterpret_cast<UCHAR *>(WorkItem->WorkerRoutine) !=
						g_DispgpPatchGuardStaticWorkItemRoutine) {
						// If it is not neither, it is not PatchGuard's work item routine.
						return false;
					}

					// If it is, it is probably PatchGuard's one. If so, try to decrypt it
					// as it should be encrypted.
					LOG_DEBUG_SAFE("Calling PatchGuardStaticWorkItemRoutine %p",
						WorkItem->WorkerRoutine);
					const auto context = reinterpret_cast<PatchGuardStaticWorkItemContext *>(
						WorkItem->Parameter);
					pgContext = reinterpret_cast<PatchGuardContext *>(
						context->EncodedWorkItemContext ^ context->XorKey);
				}
				else {
					// If it is not, it is probably PatchGuard's one.
					LOG_DEBUG_SAFE("Calling a non-image region %p", WorkItem->WorkerRoutine);
					pgContext = reinterpret_cast<PatchGuardContext *>(WorkItem->Parameter);
				}

				// Determine whether it has a pointer to ExAcquireResourceSharedLite() at
				// a specific offset.
				if (!ddk::mem_util::MmIsAccessibleAddress(&pgContext->ExAcquireResourceSharedLite)) {
					return false;
				}
				if (!ddk::mem_util::MmIsAccessibleAddress(&pgContext->ExAcquireResourceSharedLite2)) {
					return false;
				}
				return (g_ExAcquireResourceSharedLite == reinterpret_cast<ULONG_PTR>(pgContext->ExAcquireResourceSharedLite)) ||
					(g_ExAcquireResourceSharedLite == reinterpret_cast<ULONG_PTR>(pgContext->ExAcquireResourceSharedLite2));
			}
			private:
				void disable_pg_context_win10()
				{
					/*disable_pg_win10();*/
				/*	g_MmNonPagedPoolStart = new ULONG_PTR;
					*g_MmNonPagedPoolStart = 0xFFFFE00000000000;*/
					disable_pg_context();
					//KeGenericCallDpc(ddk::nt_patchguard::PgDisableDpcRoutine, nullptr);
				}
				void disable_pg_win10_workitem(DWORD cpu)
				{
					//遍历WORKITEM
					const auto exNode0 = *reinterpret_cast<ddk::ntos_space::win10_14393_x64::ENODE **>(
						reinterpret_cast<BYTE *>(KeQueryPrcbAddress(cpu)) + 0x640);
					for (auto priority = 0;
					priority <
						RTL_NUMBER_OF(exNode0->ExWorkQueue.WorkPriQueue.EntryListHead);
						++priority) {
						auto &list = exNode0->ExWorkQueue.WorkPriQueue.EntryListHead[priority];
						auto next = list.Flink;
						int index = 0;
						while (next != &list) {
							auto item = CONTAINING_RECORD(next, WORK_QUEUE_ITEM, List);
							DBG_PRINT(
							"%-3d ExWorkItem (%p) Routine (%p) Parameter (%p)\r\n", index,
							item, item->WorkerRoutine, item->Parameter);
							//这个判定有问题
							if (IsPgWorkItem10(item))
							{
								DBG_PRINT("find patchguard workitem %p\r\n", item->WorkerRoutine);
#pragma warning(push)
#pragma warning(disable : 28023)
								item->WorkerRoutine = [](void *) {};  // NOLINT(readability/function)
#pragma warning(push)
							}
							next = next->Flink;
							index++;
						}
					}
				}
				void disable_pg_win10_dpctimer(DWORD cpu)
				{
#define KTIMER_TABLE_ENTRY_MAX  (256)
					auto p_kpcr = reinterpret_cast<ddk::ntos_space::win10_14393_x64::PKPRCB>(KeQueryPrcbAddress(cpu));
					auto ptrKTimerTable = &p_kpcr->TimerTable;
					if (ptrKTimerTable)
					{
						for (auto i = 0; i < KTIMER_TABLE_ENTRY_MAX; i++)
						{
							auto ptrListEntryHead = &(ptrKTimerTable->TimerEntries[i].Entry);
							for (auto ptrListEntry = ptrListEntryHead->Flink;
							ptrListEntry != ptrListEntryHead;
								ptrListEntry = ptrListEntry->Flink)
							{
								auto ptrTimer = CONTAINING_RECORD(ptrListEntry, KTIMER, TimerListEntry);
								if (!MmIsAddressValid(ptrTimer))
									continue;

								if (!ptrTimer->Dpc)
									continue;

								hack_win10_timer(ptrTimer);
							}
						}
					}
				}
				void hack_win10_timer(PKTIMER pTimer)
				{
#define p2dq(x)  (*((ULONG_PTR*)x))

					ULONG_PTR  ptrDpc = (ULONG_PTR)pTimer->Dpc;
					KDPC*    DecDpc = NULL;
					int      nShift = (p2dq(g_KiWaitNever) & 0xFF);

					//_RSI->Dpc = (_KDPC *)v19;
					//_RSI = Timer;
					ptrDpc ^= p2dq(g_KiWaitNever);//v19 = KiWaitNever ^ v18;
					ptrDpc = _rotl64(ptrDpc, nShift);//v18 = __ROR8__((unsigned __int64)Timer ^ _RBX, KiWaitNever);
					ptrDpc ^= (ULONG_PTR)pTimer;
					ptrDpc = _byteswap_uint64(ptrDpc);//__asm { bswap   rbx }
					ptrDpc ^= p2dq(g_KiWaitAlways);//_RBX = (unsigned __int64)DPC ^ KiWaitAlways;
													//real DPC
					if (MmIsAddressValid((PVOID)ptrDpc))
					{
						auto DecDpc = (KDPC*)ptrDpc;
						UCHAR *base = nullptr;
						RtlPcToFileHeader(DecDpc->DeferredRoutine, reinterpret_cast<void **>(&base));
						if (base)
						{
							if (ddk::mem_util::MmIsAddressNonCanonical(DWORD64(DecDpc->DeferredContext)))
							{
								//PG
								DBG_PRINT("Find PG Timer1\r\n");
								pTimer->DueTime.QuadPart = (ddk::util::time::minutes(60) * LONGLONG(-72));
							}
						}
						else
						{
							DBG_PRINT("Find PG Timer2\r\n");
							//PG
							pTimer->DueTime.QuadPart = (ddk::util::time::minutes(60) * LONGLONG(-72));
						}
					}
				}
			public:
				void disable_pg_win10()
				{
					auto cpunumber = KeQueryActiveProcessorCount(nullptr);
					for (auto i = DWORD(0); i < cpunumber;i++)
					{
						disable_pg_win10_workitem(i);

						disable_pg_win10_dpctimer(i);

					}
					auto p_kpcr = reinterpret_cast<UCHAR *>(KeQueryPrcbAddress(0));
					if (p_kpcr)
					{
						auto p_halTimer = reinterpret_cast<ULONG_PTR *>(p_kpcr + 0x660);
						auto p_halEvent = reinterpret_cast<ULONG_PTR *>(p_kpcr + 0x630);
						if (p_halTimer)
						{
							*p_halTimer = 0;
						}
						if (p_halEvent)
						{
							*p_halEvent = 0;
						}
					}

					if (g_KiBalanceSetManagerPeriodicDpc)
					{
						auto p_x = reinterpret_cast<KDPC *>(g_KiBalanceSetManagerPeriodicDpc);
						p_x->DeferredRoutine = ddk::nt_patchguard::DispgpTinyPatchGuardDpcRoutineHookHandler;
					}
				}
			public:
				static VOID PgDisableDpcRoutine(
					_In_ struct _KDPC *Dpc,
					_In_opt_ PVOID DeferredContext,
					_In_opt_ PVOID SystemArgument1,
					_In_opt_ PVOID SystemArgument2
					)
				{
					ddk::nt_patchguard::getInstance().disable_pg_win10();
					KeSignalCallDpcSynchronize(SystemArgument2);
					KeSignalCallDpcDone(SystemArgument1);

				}
			public:
				PatchGuardContexts info;
				void scanner_callback_seh(PVOID Va, SIZE_T VaSize)
				{
					__try
					{
						scanner_callback(Va, VaSize);
					}
					__except (1)
					{
						DBG_PRINT("seh %p\r\n", Va);
					}
				}
				
				bool scanner_callback(PVOID Va, SIZE_T MemSize)
				{
					//VA
					auto StartAddress = reinterpret_cast<ULONG_PTR>(Va);
					for (SIZE_T searchedBytes = 0; searchedBytes < MemSize; /**/)
					{
						// Search a context
						PatchGuardContextInfo result = {};
						const auto remainingBytes = MemSize - searchedBytes;
						const auto searchPosition = StartAddress + searchedBytes;
						const auto checkedBytes = SearchPatchGuardContext(
							searchPosition, remainingBytes, result);//这里有很奇怪的问题，那就是为何Win8.1和Win10上搜不到呢？
						searchedBytes += checkedBytes;

						// Check if a context was found
						if (result.PgContext)
						{
							result.phyAddr = MmGetPhysicalAddress(PVOID(result.PgContext));
							DBG_PRINT("Likely PatchGuard %016llX : XorKey %016llX\r\n",
								result.PgContext, result.XorKey);
							if (check_pg_context(result))
							{
								add_pg_context(result);
								DBG_PRINT("Real PatchGuard %016llX :%p: XorKey %016llX\r\n",
									result.PgContext,PVOID(result.phyAddr.QuadPart), result.XorKey);
							}
						}
					}
					return true;
				}
				SIZE_T SearchPatchGuardContext(
					__in ULONG_PTR SearchBase,
					__in SIZE_T SearchSize,
					__out PatchGuardContextInfo& Result)
				{
					const auto maxSearchSize =
						SearchSize - sizeof(CmpAppendDllSection_PATTERN);
					for (SIZE_T searchedBytes = 0; searchedBytes < maxSearchSize;
					++searchedBytes)
					{
						const auto addressToBeChecked =
							reinterpret_cast<ULONG64*>(SearchBase + searchedBytes);

						//// PatchGuard contexts never have the same value on their first some
						//// bytes.
						//if (addressToBeChecked[0] == addressToBeChecked[1])
						//{
						//	continue;
						//}

						// Here is the best part; as we know the decrypted form of PatchGuard
						// context, namely CmpAppendDllSection, we can deduce a possible XOR key
						// by doing XOR with CmpAppendDllSection and code of the current address.
						// At this moment, possibleXorKey may or may not be a right one, but by
						// decrypting code with the key, we can see if it generates correct
						// decrypted pattern (CmpAppendDllSection). If it showed the pattern,
						// it is a correct XOR key. Do it with WinXpIsCmpAppendDllSection.
						const auto possibleXorKey =
							addressToBeChecked[1] ^ CmpAppendDllSection_PATTERN[1];
						if (!IsCmpAppendDllSection(addressToBeChecked, possibleXorKey))
						{
							continue;
						}

						// A PatchGuard context was found
						Result.PgContext = reinterpret_cast<ULONG_PTR>(addressToBeChecked);
						Result.XorKey = possibleXorKey;
						return searchedBytes + 1;
					}
					return SearchSize;
				}
				bool IsCmpAppendDllSection(
					__in const ULONG64* AddressToBeChecked,
					__in ULONG64 PossibleXorKey)
				{
					const auto NUMBER_OF_TIMES_TO_COMPARE =
						sizeof(CmpAppendDllSection_PATTERN) / sizeof(ULONG64);
					C_ASSERT(NUMBER_OF_TIMES_TO_COMPARE == 19);

					for (int i = 2; i < NUMBER_OF_TIMES_TO_COMPARE; ++i)
					{
						const auto decryptedContents = AddressToBeChecked[i] ^ PossibleXorKey;
						if (decryptedContents != CmpAppendDllSection_PATTERN[i])
						{
							return false;
						}
					}
					return true;
				}
				bool check_pg_context(PatchGuardContextInfo result)
				{
					__try
					{
						static UCHAR m_PgBack[0x8000] = {};
						static auto m_PgBack_Pa = MmGetPhysicalAddress(PVOID(m_PgBack));
						RtlZeroBytes(m_PgBack, sizeof(m_PgBack));
						//DBG_PRINT("PgBack Phyaddr = %p\r\n", PVOID(m_PgBack_Pa.QuadPart));
						if (m_PgBack_Pa.QuadPart == MmGetPhysicalAddress(PVOID(result.PgContext)).QuadPart)
						{
							//DBG_PRINT("zhenxiang\r\n");
							return false;
						}
						if (result.XorKey)
						{
							RtlCopyMemory(m_PgBack, PVOID(result.PgContext), sizeof(PgContextBase10));
							if (ddk::util::IsWindows10())
							{
								auto pgContext = reinterpret_cast<ULONG64*>(m_PgBack);
								static const auto NUMBER_OF_TIMES_TO_DECRYPT =
									FIELD_OFFSET(PgContextBase10, unknown2)
									/ sizeof(ULONG64);
								C_ASSERT(NUMBER_OF_TIMES_TO_DECRYPT == 0x19);
								for (SIZE_T i = 0; i < NUMBER_OF_TIMES_TO_DECRYPT; ++i)
								{
									pgContext[i] ^= result.XorKey;
								}

								// The above decrypts ContextSizeInQWord field, so let's decrypt the
								// remaining bytes according to the value. Note that this decryption
								// requires key location.
								auto decryptionKey = result.XorKey;
								auto decryptedPgContext = reinterpret_cast<PgContextBase10*>(pgContext);
								DBG_PRINT("win10 PgSizeInQowrd = %x\r\n", decryptedPgContext->ContextSizeInQWord);
								//再复制一次
								//RtlCopyMemory(&pgContext[NUMBER_OF_TIMES_TO_DECRYPT], PVOID(result.PgContext + 0xC0),decryptedPgContext->ContextSizeInQWord*8);
								for (auto i = decryptedPgContext->ContextSizeInQWord; i; --i)
								{
									pgContext[i + NUMBER_OF_TIMES_TO_DECRYPT - 1] ^= decryptionKey;
									decryptionKey = _rotr64(decryptionKey, static_cast<UCHAR>(i));
								}
								if (decryptedPgContext->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
								{
									return true;
								}
							}
							else
							{
								auto pgContext = reinterpret_cast<ULONG64*>(m_PgBack);
								static const auto NUMBER_OF_TIMES_TO_DECRYPT =
									FIELD_OFFSET(PgContextBase, ExAcquireResourceSharedLite)
									/ sizeof(ULONG64);
								C_ASSERT(NUMBER_OF_TIMES_TO_DECRYPT == 0x19);
								for (SIZE_T i = 0; i < NUMBER_OF_TIMES_TO_DECRYPT; ++i)
								{
									pgContext[i] ^= result.XorKey;
								}

								// The above decrypts ContextSizeInQWord field, so let's decrypt the
								// remaining bytes according to the value. Note that this decryption
								// requires key location.
								auto decryptionKey = result.XorKey;
								auto decryptedPgContext = reinterpret_cast<PgContextBase*>(pgContext);
								DBG_PRINT("PgSizeInQowrd = %x\r\n", decryptedPgContext->ContextSizeInQWord);
								for (auto i = decryptedPgContext->ContextSizeInQWord; i; --i)
								{
									pgContext[i + NUMBER_OF_TIMES_TO_DECRYPT - 1] ^= decryptionKey;
									decryptionKey = _rotr64(decryptionKey, static_cast<UCHAR>(i));
								}
								if (decryptedPgContext->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
								{
									return true;
								}
							}
						}
						else
						{

							if (ddk::util::IsWindows10())
							{
								auto pg = reinterpret_cast<PgContextBase10*>(result.PgContext);
								if (pg->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
								{
									return true;
								}
							}
							else
							{
								auto pg = reinterpret_cast<PgContextBase*>(result.PgContext);
								if (pg->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
								{
									return true;
								}
							}
						}
					}
					__except (1) {

					}
					return false;
				}
				void add_pg_context(PatchGuardContextInfo result)
				{
					for (auto i = 0; i < info.NumberOfPgContexts;i++)
					{
						if (info.PgContexts[i].phyAddr.QuadPart == result.phyAddr.QuadPart)
						{
							DBG_PRINT("Same PhyAddr\r\n");
							return;
						}
					}
					info.PgContexts[info.NumberOfPgContexts] = result;
					info.NumberOfPgContexts++;
				}
				void search_pg_context(PUNICODE_STRING RegPath)
				{
					RtlStringCchPrintfW(g_DispgpRegistryKey,
						RTL_NUMBER_OF(g_DispgpRegistryKey), L"%wZ",
						RegPath);

					loadSymbols();

					UNICODE_STRING procName =
						RTL_CONSTANT_STRING(L"ExAcquireResourceSharedLite");
					const auto realAddress =
						reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&procName));
					if (!g_ExAcquireResourceSharedLite)
						g_ExAcquireResourceSharedLite = realAddress;
					//暴力搜索，兼容性很好，最好不拿来做修改!!!!
					//有时候也会漏
					can_write = false;
					info.NumberOfPgContexts = 0;
					//win7 win8 win8.1 win10
					ddk::PhysicalMemScan::getInstance().Scanner(std::bind(&ddk::nt_patchguard::scanner_callback,this, std::placeholders::_1,
						std::placeholders::_2));
					//对比另一个搜索结果
					if(!ddk::util::IsWindows8OrGreater())
						disable_pg_context();//这个在Win7没问题
					return;
					//下面只是POC
					//只有对VA的内存做暴力搜索，拿来做修改比较稳定，但是错漏多
					//can_write = true;
					//TODO:如何遍历全部VA的内存呢？
					//Pool遍历 NonPagedPool判断在Win8,win8.1 win10没用卵用
					DBG_PRINT("Pool Search\r\n");
					auto NumberOfBigPageTable = *g_PoolBigPageTableSize;
					auto BigPageTable = *g_PoolBigPageTable;
					for (SIZE_T i = 0; i < NumberOfBigPageTable;++i)
					{
						auto Entry = &BigPageTable[i];
						auto startAddress = reinterpret_cast<ULONG_PTR>(Entry->Va);
						auto Size = Entry->Size;
						if (!startAddress || (startAddress&1))
						{
							continue;
						}
						if (Size<sizeof(PgContextBase10))
						{
							continue;
						}
						bool b_valid = true;
						for (SIZE_T p = 0; p < Size ;p+=PAGE_SIZE)
						{
							if (!MmIsAddressValid(PVOID(startAddress+p)))
							{
								b_valid = false;
								break;
							}
						}
						if (!b_valid)
						{
							DBG_PRINT("no vaild %p %x\r\n", PVOID(startAddress),Size);
							continue;
						}
						//DBG_PRINT("Scan Pool %p %x\r\n", PVOID(startAddress), Size);
						scanner_callback_seh(PVOID(startAddress), Size);
					}
					//IndependedPage遍历
					DBG_PRINT("Scan IndependedPages\r\n");
					//IndependedPage的Scan要用比较奇葩的思路
					//mmSystemRangeStart到PXE-TOP这块内存上遍历
					ddk::mm_independ_scan::getInstance().scanner(std::bind(&ddk::nt_patchguard::scanner_callback_seh, this, std::placeholders::_1,
						std::placeholders::_2));
				}
	};
};