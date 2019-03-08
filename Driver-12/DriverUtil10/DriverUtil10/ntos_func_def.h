#pragma once
extern "C"
{
#ifndef _SYSTEM_INFORMATION_CLASS
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0,
		SystemProcessorInformation = 1,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemPathInformation = 4,
		SystemProcessInformation = 5,
		SystemCallCountInformation = 6,
		SystemDeviceInformation = 7,
		SystemProcessorPerformanceInformation = 8,
		SystemFlagsInformation = 9,
		SystemCallTimeInformation = 10,
		SystemModuleInformation = 11,
		SystemLocksInformation = 12,
		SystemStackTraceInformation = 13,
		SystemPagedPoolInformation = 14,
		SystemNonPagedPoolInformation = 15,
		SystemHandleInformation = 16,
		SystemObjectInformation = 17,
		SystemPageFileInformation = 18,
		SystemVdmInstemulInformation = 19,
		SystemVdmBopInformation = 20,
		SystemFileCacheInformation = 21,
		SystemPoolTagInformation = 22,
		SystemInterruptInformation = 23,
		SystemDpcBehaviorInformation = 24,
		SystemFullMemoryInformation = 25,
		SystemLoadGdiDriverInformation = 26,
		SystemUnloadGdiDriverInformation = 27,
		SystemTimeAdjustmentInformation = 28,
		SystemSummaryMemoryInformation = 29,
		SystemMirrorMemoryInformation = 30,
		SystemPerformanceTraceInformation = 31,
		SystemObsolete0 = 32,
		SystemExceptionInformation = 33,
		SystemCrashDumpStateInformation = 34,
		SystemKernelDebuggerInformation = 35,
		SystemContextSwitchInformation = 36,
		SystemRegistryQuotaInformation = 37,
		SystemExtendServiceTableInformation = 38,
		SystemPrioritySeperation = 39,
		SystemVerifierAddDriverInformation = 40,
		SystemVerifierRemoveDriverInformation = 41,
		SystemProcessorIdleInformation = 42,
		SystemLegacyDriverInformation = 43,
		SystemCurrentTimeZoneInformation = 44,
		SystemLookasideInformation = 45,
		SystemTimeSlipNotification = 46,
		SystemSessionCreate = 47,
		SystemSessionDetach = 48,
		SystemSessionInformation = 49,
		SystemRangeStartInformation = 50,
		SystemVerifierInformation = 51,
		SystemVerifierThunkExtend = 52,
		SystemSessionProcessInformation = 53,
		SystemLoadGdiDriverInSystemSpace = 54,
		SystemNumaProcessorMap = 55,
		SystemPrefetcherInformation = 56,
		SystemExtendedProcessInformation = 57,
		SystemRecommendedSharedDataAlignment = 58,
		SystemComPlusPackage = 59,
		SystemNumaAvailableMemory = 60,
		SystemProcessorPowerInformation = 61,
		SystemEmulationBasicInformation = 62,
		SystemEmulationProcessorInformation = 63,
		SystemExtendedHandleInformation = 64,
		SystemLostDelayedWriteInformation = 65,
		SystemBigPoolInformation = 66,
		SystemSessionPoolTagInformation = 67,
		SystemSessionMappedViewInformation = 68,
		SystemHotpatchInformation = 69,
		SystemObjectSecurityMode = 70,
		SystemWatchdogTimerHandler = 71,
		SystemWatchdogTimerInformation = 72,
		SystemLogicalProcessorInformation = 73,
		SystemWow64SharedInformationObsolete = 74,
		SystemRegisterFirmwareTableInformationHandler = 75,
		SystemFirmwareTableInformation = 76,
		SystemModuleInformationEx = 77,
		SystemVerifierTriageInformation = 78,
		SystemSuperfetchInformation = 79,
		SystemMemoryListInformation = 80,
		SystemFileCacheInformationEx = 81,
		SystemThreadPriorityClientIdInformation = 82,
		SystemProcessorIdleCycleTimeInformation = 83,
		SystemVerifierCancellationInformation = 84,
		SystemProcessorPowerInformationEx = 85,
		SystemRefTraceInformation = 86,
		SystemSpecialPoolInformation = 87,
		SystemProcessIdInformation = 88,
		SystemErrorPortInformation = 89,
		SystemBootEnvironmentInformation = 90,
		SystemHypervisorInformation = 91,
		SystemVerifierInformationEx = 92,
		SystemTimeZoneInformation = 93,
		SystemImageFileExecutionOptionsInformation = 94,
		SystemCoverageInformation = 95,
		SystemPrefetchPatchInformation = 96,
		SystemVerifierFaultsInformation = 97,
		SystemSystemPartitionInformation = 98,
		SystemSystemDiskInformation = 99,
		SystemProcessorPerformanceDistribution = 100,
		SystemNumaProximityNodeInformation = 101,
		SystemDynamicTimeZoneInformation = 102,
		SystemCodeIntegrityInformation = 103,
		SystemProcessorMicrocodeUpdateInformation = 104,
		SystemProcessorBrandString = 105,
		SystemVirtualAddressInformation = 106,
		SystemLogicalProcessorAndGroupInformation = 107,
		SystemProcessorCycleTimeInformation = 108,
		SystemStoreInformation = 109,
		SystemRegistryAppendString = 110,
		SystemAitSamplingValue = 111,
		SystemVhdBootInformation = 112,
		SystemCpuQuotaInformation = 113,
		SystemNativeBasicInformation = 114,
		SystemErrorPortTimeouts = 115,
		SystemLowPriorityIoInformation = 116,
		SystemBootEntropyInformation = 117,
		SystemVerifierCountersInformation = 118,
		SystemPagedPoolInformationEx = 119,
		SystemSystemPtesInformationEx = 120,
		SystemNodeDistanceInformation = 121,
		SystemAcpiAuditInformation = 122,
		SystemBasicPerformanceInformation = 123,
		SystemQueryPerformanceCounterInformation = 124,
		SystemSessionBigPoolInformation = 125,
		SystemBootGraphicsInformation = 126,
		SystemScrubPhysicalMemoryInformation = 127,
		SystemBadPageInformation = 128,
		SystemProcessorProfileControlArea = 129,
		SystemCombinePhysicalMemoryInformation = 130,
		SystemEntropyInterruptTimingInformation = 131,
		SystemConsoleInformation = 132,
		SystemPlatformBinaryInformation = 133,
		SystemPolicyInformation = 134,
		SystemHypervisorProcessorCountInformation = 135,
		SystemDeviceDataInformation = 136,
		SystemDeviceDataEnumerationInformation = 137,
		SystemMemoryTopologyInformation = 138,
		SystemMemoryChannelInformation = 139,
		SystemBootLogoInformation = 140,
		SystemProcessorPerformanceInformationEx = 141,
		SystemSpare0 = 142,
		SystemSecureBootPolicyInformation = 143,
		SystemPageFileInformationEx = 144,
		SystemSecureBootInformation = 145,
		SystemEntropyInterruptTimingRawInformation = 146,
		SystemPortableWorkspaceEfiLauncherInformation = 147,
		SystemFullProcessInformation = 148,
		SystemKernelDebuggerInformationEx = 149,
		SystemBootMetadataInformation = 150,
		SystemSoftRebootInformation = 151,
		SystemElamCertificateInformation = 152,
		SystemOfflineDumpConfigInformation = 153,
		SystemProcessorFeaturesInformation = 154,
		SystemRegistryReconciliationInformation = 155,
		SystemEdidInformation = 156,
		MaxSystemInfoClass = 157
	} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
#endif

#ifndef SYSTEM_PROCESS_INFORMATION
	typedef struct _SYSTEM_THREAD_INFORMATION
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		KWAIT_REASON WaitReason;
	}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER SpareLi1;
		LARGE_INTEGER SpareLi2;
		LARGE_INTEGER SpareLi3;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR PageDirectoryBase;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
		SYSTEM_THREAD_INFORMATION thread_info[1];
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
#endif
	typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		UCHAR Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


	typedef struct _PEB
	{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR BitField;
		PVOID Mutant;
		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PVOID ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PVOID FastPebLock;
		PVOID AtlThunkSListPtr;
		PVOID IFEOKey;
		PVOID CrossProcessFlags;
		PVOID UserSharedInfoPtr;
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		PVOID ApiSetMap;
	} PEB, *PPEB;

	typedef struct _PEB_LDR_DATA32
	{
		ULONG Length;
		UCHAR Initialized;
		ULONG SsHandle;
		LIST_ENTRY32 InLoadOrderModuleList;
		LIST_ENTRY32 InMemoryOrderModuleList;
		LIST_ENTRY32 InInitializationOrderModuleList;
	} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

	typedef struct _LDR_DATA_TABLE_ENTRY32
	{
		LIST_ENTRY32 InLoadOrderLinks;
		LIST_ENTRY32 InMemoryOrderLinks;
		LIST_ENTRY32 InInitializationOrderLinks;
		ULONG DllBase;
		ULONG EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING32 FullDllName;
		UNICODE_STRING32 BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY32 HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

	typedef struct _PEB32
	{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR BitField;
		ULONG Mutant;
		ULONG ImageBaseAddress;
		ULONG Ldr;
		ULONG ProcessParameters;
		ULONG SubSystemData;
		ULONG ProcessHeap;
		ULONG FastPebLock;
		ULONG AtlThunkSListPtr;
		ULONG IFEOKey;
		ULONG CrossProcessFlags;
		ULONG UserSharedInfoPtr;
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		ULONG ApiSetMap;
	} PEB32, *PPEB32;

	typedef struct _WOW64_PROCESS
	{
		PPEB32 Wow64;
	} WOW64_PROCESS, *PWOW64_PROCESS;

	typedef union _WOW64_APC_CONTEXT
	{
		struct
		{
			ULONG Apc32BitContext;
			ULONG Apc32BitRoutine;
		};

		PVOID Apc64BitContext;

	} WOW64_APC_CONTEXT, *PWOW64_APC_CONTEXT;

	typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
	{
		ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
		SIZE_T Size;
		ULONG_PTR Value;
		ULONG Unknown;
	} NT_PROC_THREAD_ATTRIBUTE_ENTRY, *NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

	typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
	{
		ULONG Length;
		NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
	} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;

//#ifndef NON_PAGED_DEBUG_INFO
//	typedef struct _NON_PAGED_DEBUG_INFO
//	{
//		USHORT      Signature;
//		USHORT      Flags;
//		ULONG       Size;
//		USHORT      Machine;
//		USHORT      Characteristics;
//		ULONG       TimeDateStamp;
//		ULONG       CheckSum;
//		ULONG       SizeOfImage;
//		ULONGLONG   ImageBase;
//	} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;
//#endif
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		PVOID ExceptionTable;
		ULONG ExceptionTableSize;
		// ULONG padding on IA64
		PVOID GpValue;
		PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT __Unused5;
		PVOID SectionPointer;
		ULONG CheckSum;
		// ULONG padding on IA64
		PVOID LoadedImports;
		PVOID PatchInformation;
	} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


#define ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID    (0x00000001)
#define ACTCTX_FLAG_LANGID_VALID                    (0x00000002)
#define ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID        (0x00000004)
#define ACTCTX_FLAG_RESOURCE_NAME_VALID             (0x00000008)
#define ACTCTX_FLAG_SET_PROCESS_DEFAULT             (0x00000010)
#define ACTCTX_FLAG_APPLICATION_NAME_VALID          (0x00000020)
#define ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF           (0x00000040)
#define ACTCTX_FLAG_HMODULE_VALID                   (0x00000080)

	typedef struct tagACTCTXW
	{
		ULONG  cbSize;
		ULONG  dwFlags;
		PWCH   lpSource;
		USHORT wProcessorArchitecture;
		USHORT wLangId;
		PWCH   lpAssemblyDirectory;
		PWCH   lpResourceName;
		PWCH   lpApplicationName;
		PVOID  hModule;
	} ACTCTXW, *PACTCTXW;

	typedef struct tagACTCTXW32
	{
		ULONG  cbSize;
		ULONG  dwFlags;
		ULONG  lpSource;
		USHORT wProcessorArchitecture;
		USHORT wLangId;
		ULONG  lpAssemblyDirectory;
		ULONG  lpResourceName;
		ULONG  lpApplicationName;
		ULONG  hModule;
	} ACTCTXW32, *PACTCTXW32;

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwOpenProcessToken(
			IN HANDLE       ProcessHandle,
			IN ACCESS_MASK  DesiredAccess,
			OUT PHANDLE     TokenHandle
			);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ObReferenceObjectByName(
			IN PUNICODE_STRING objectName,
			IN ULONG Attributes,
			IN PACCESS_STATE PassedAccessState OPTIONAL,
			IN ACCESS_MASK DesiredAccess OPTIONAL,
			IN POBJECT_TYPE objectType,
			IN KPROCESSOR_MODE AccessMode,
			IN OUT PVOID ParseContext OPTIONAL,
			OUT PVOID *Object
			);

	NTSYSAPI 
		PVOID 
		NTAPI 
		RtlPcToFileHeader(
		_In_ PVOID PcValue,
		_Out_ PVOID *BaseOfImage
			);
	
	NTSYSAPI
		VOID
		NTAPI
		KeGenericCallDpc(
			_In_ PKDEFERRED_ROUTINE Routine,
			_In_opt_ PVOID Context
			);

	NTSYSAPI
		VOID
		NTAPI
		KeSignalCallDpcDone(
			_In_ PVOID SystemArgument1
			);

	NTSYSAPI
	LOGICAL
		NTAPI
		KeSignalCallDpcSynchronize(
			_In_ PVOID SystemArgument2
			);

	NTSYSAPI
		PVOID
		NTAPI
		KeQueryPrcbAddress(
			__in ULONG Number
			);

	NTSYSAPI
		PVOID
		NTAPI
		RtlImageDirectoryEntryToData(
			IN PVOID Base,
			IN BOOLEAN MappedAsImage,
			IN USHORT DirectoryEntry,
			OUT PULONG Size
			);

	NTSYSAPI
		PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(
			PVOID Base
			);

	NTSYSAPI
		PCCHAR
		NTAPI
		PsGetProcessImageFileName(
			IN PEPROCESS Process
			);

	NTSYSAPI BOOLEAN NTAPI PsIsProtectedProcess(IN PEPROCESS Process);

	NTSYSAPI
		PVOID
		NTAPI
		PsGetProcessPeb(IN PEPROCESS Process);

	NTSYSAPI
		PVOID
		NTAPI
		PsGetProcessWow64Process(IN PEPROCESS Process);

	NTSYSAPI
		PVOID
		NTAPI
		PsGetCurrentProcessWow64Process();

	NTSYSAPI
		PVOID
		NTAPI
		PsGetThreadTeb(IN PETHREAD Thread);

	NTSYSAPI
		BOOLEAN
		NTAPI
		PsIsThreadTerminating(
			__in PETHREAD Thread
			);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwQuerySystemInformation(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID                   SystemInformation,
			IN ULONG                    Length,
			OUT PULONG                  ReturnLength
			);

	typedef VOID(NTAPI *PKNORMAL_ROUTINE)
		(
			PVOID NormalContext,
			PVOID SystemArgument1,
			PVOID SystemArgument2
			);

	typedef VOID(NTAPI* PKKERNEL_ROUTINE)
		(
			PRKAPC Apc,
			PKNORMAL_ROUTINE *NormalRoutine,
			PVOID *NormalContext,
			PVOID *SystemArgument1,
			PVOID *SystemArgument2
			);

	typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(PRKAPC Apc);
	typedef enum _KAPC_ENVIRONMENT
	{
		OriginalApcEnvironment,
		AttachedApcEnvironment,
		CurrentApcEnvironment,
		InsertApcEnvironment
	} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

	NTSYSAPI
		VOID
		NTAPI
		KeInitializeApc(
			IN PKAPC Apc,
			IN PKTHREAD Thread,
			IN KAPC_ENVIRONMENT ApcStateIndex,
			IN PKKERNEL_ROUTINE KernelRoutine,
			IN PKRUNDOWN_ROUTINE RundownRoutine,
			IN PKNORMAL_ROUTINE NormalRoutine,
			IN KPROCESSOR_MODE ApcMode,
			IN PVOID NormalContext
			);

	NTSYSAPI
		BOOLEAN
		NTAPI
		KeInsertQueueApc(
			PKAPC Apc,
			PVOID SystemArgument1,
			PVOID SystemArgument2,
			KPRIORITY Increment
			);

	NTSYSAPI
		BOOLEAN
		NTAPI
		KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

	extern POBJECT_TYPE *IoDeviceObjectType;
	extern POBJECT_TYPE *IoDriverObjectType;
	extern PSHORT NtBuildNumber;
	//NTSYSAPI
	//	NTSTATUS
	//	NTAPI
	//	IoCreateDriver(
	//		IN PUNICODE_STRING DriverName,
	//		IN PDRIVER_INITIALIZE InitializationFunction
	//		);
	typedef struct _OBJECT_DIRECTORY_INFORMATION
	{
		UNICODE_STRING Name;
		UNICODE_STRING TypeName;
	} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;
	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwQueryDirectoryObject(
			__in HANDLE DirectoryHandle,
			__out_bcount_opt(Length) PVOID Buffer,
			__in ULONG Length,
			__in BOOLEAN ReturnSingleEntry,
			__in BOOLEAN RestartScan,
			__inout PULONG Context,
			__out_opt PULONG ReturnLength
			);
	
	typedef struct _OBJECT_DIRECTORY                     // 6 elements, 0x150 bytes (sizeof) 
	{
		struct _OBJECT_DIRECTORY_ENTRY* HashBuckets[37];
	}OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

	typedef struct _OBJECT_DIRECTORY_ENTRY         // 3 elements, 0x18 bytes (sizeof) 
	{
		/*0x000*/     struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
		/*0x008*/     VOID*        Object;
		/*0x010*/     ULONG32      HashValue;
	}OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;
}
using fnPsReferenceProcessFilePointer = NTSTATUS(NTAPI *) (IN PEPROCESS, OUT PFILE_OBJECT *);
using fnIoCreateDriver = NTSTATUS(NTAPI*)(PUNICODE_STRING, PDRIVER_INITIALIZE);
using fnIoDeleteDriver = VOID(NTAPI*)(PDRIVER_OBJECT);