#include "Base.h"
#include "Utils.h"
#include "nt_patchguard.h"

EXTERN_C NTSTATUS DispgKeWaitForSingleObjectHookHandler(
	NTSTATUS OriginalReturnValue, ULONG_PTR StackPointer) {
	ddk::nt_patchguard::getInstance().handler_KeWaitForSingleObject(StackPointer);
	return OriginalReturnValue;
}
EXTERN_C NTSTATUS DispgKeDelayExecutionThreadHookHandler(
	NTSTATUS OriginalReturnValue, ULONG_PTR StackPointer) {
	ddk::nt_patchguard::getInstance().handler_KeDelayExecutionThread(StackPointer);
	return OriginalReturnValue;
}

EXTERN_C void DispgWaitForever() {
	PAGED_CODE();
	LOG_DEBUG_SAFE("Wait forever");

	// Wait until this thread ends == never returns
	auto status = KeWaitForSingleObject(PsGetCurrentThread(), Executive,
		KernelMode, FALSE, nullptr);

	LOG_ERROR_SAFE("Oops!! %p", status);
	DBG_BREAK();
}

EXTERN_C WORK_QUEUE_ITEM *
DispgDequeuingWorkItemRoutineHookHandler(WORK_QUEUE_ITEM *WorkItem) {
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return WorkItem;
	}

	if (!ddk::nt_patchguard::getInstance().IsPatchGuardWorkItem(WorkItem)) {
		return WorkItem;
	}

	LOG_INFO_SAFE("PatchGuard detected (calling %p).", WorkItem->WorkerRoutine);
#pragma warning(push)
#pragma warning(disable : 28023)
	WorkItem->WorkerRoutine = [](void *) {};  // NOLINT(readability/function)
#pragma warning(push)
	return WorkItem;
}
