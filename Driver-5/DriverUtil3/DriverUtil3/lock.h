#pragma once
#include "Base.h"
namespace ddk
{
	class nt_spinlock
	{
	public:
		nt_spinlock()
		{
			KeInitializeSpinLock(&spinlock);
		}
		~nt_spinlock()
		{

		}
		void lock(PKLOCK_QUEUE_HANDLE handle)
		{
			if (KeGetCurrentIrql() < DISPATCH_LEVEL)
				KeAcquireInStackQueuedSpinLock(&spinlock, handle);
			else
				KeAcquireInStackQueuedSpinLockAtDpcLevel(&spinlock, handle);
		}
		void unlock(PKLOCK_QUEUE_HANDLE handle)
		{
			if (handle->OldIrql < DISPATCH_LEVEL)
				KeReleaseInStackQueuedSpinLock(handle);
			else
				KeReleaseInStackQueuedSpinLockFromDpcLevel(handle);
		}
	private:
		KSPIN_LOCK spinlock;
	};
	class nt_rwlock
	{
	public:
		nt_rwlock()
		{
			res = nullptr;
			res = reinterpret_cast<PERESOURCE>(malloc(PAGE_SIZE));
			NT_ASSERT(res != nullptr);
			NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
			res_ns = ExInitializeResourceLite(res);
		}
		~nt_rwlock()
		{
			NT_ASSERT(res != nullptr);
			NT_ASSERT(res_ns == STATUS_SUCCESS);
			ExDeleteResourceLite(res);
			free(res);
		}
		void lock_for_read()
		{
			NT_ASSERT(res != nullptr);
			NT_ASSERT(res_ns == STATUS_SUCCESS);
			NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
			ExEnterCriticalRegionAndAcquireResourceShared(res);
		}
		void lock_for_write()
		{
			NT_ASSERT(res != nullptr);
			NT_ASSERT(res_ns == STATUS_SUCCESS);
			NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
			ExEnterCriticalRegionAndAcquireResourceExclusive(res);
		}
		void unlock()
		{
			NT_ASSERT(res != nullptr);
			NT_ASSERT(res_ns == STATUS_SUCCESS);
			ExReleaseResourceAndLeaveCriticalRegion(res);
		}
	private:
		PERESOURCE res;
		NTSTATUS res_ns;
	};
	class nt_mutex
	{
	public:
		nt_mutex()
		{
			KeInitializeGuardedMutex(&mutex);
		}
		~nt_mutex()
		{

		}
		void lock()
		{
			NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
			KeAcquireGuardedMutex(&mutex);
		}
		void unlock()
		{
			KeReleaseGuardedMutex(&mutex);
		}
		bool try_lock()
		{
			NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
			if (!KeTryToAcquireGuardedMutex(&mutex)) return false;
			return true;
		}
	private:
		KGUARDED_MUTEX mutex;
	};

	class nt_lock
	{
	public:
		nt_lock()
		{
			llock = 0;
		}
		~nt_lock()
		{

		}
		void lock()
		{
			while (InterlockedCompareExchange(&llock, 0, 0))
			{
				_mm_pause();
			}
			InterlockedIncrement(&llock);
		}
		void unlock()
		{
			InterlockedDecrement(&llock);
		}
	private:
		LONG llock;
	};
};