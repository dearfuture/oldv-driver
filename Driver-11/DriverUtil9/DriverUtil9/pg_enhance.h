#pragma once
#include "Base.h"
#include "cpu_lock.h"
#include "PgContext.h"
#include "util_version.h"
extern "C"
{
	static void FakeExQueueWorkItem(void *work_item,
		void *queue_type) {
		UNREFERENCED_PARAMETER(work_item);
		UNREFERENCED_PARAMETER(queue_type);
		//这里Win10 KMODE蓝屏??
		return;
	}
}
namespace ddk
{
	namespace pg_enhance_data
	{
		static const auto PG_BACK_SIZE = 0x100000;
		// Change it to 0xCC when you want to install break points for patched code
		static const UCHAR WINX_HOOK_CODE = 0x90;

		// Offset in bytes to install patch on CmpAppendDllSection
		static const ULONG WINX_HOOK_OFFSET = 8;

		// Code taken from SdbpCheckDll. Take long enough code to avoid false positive.
		static const ULONG64 WINX_SdbpCheckDll_PATTERN[] =
		{
			0x7C8B483024748B48,
			0x333824548B4C2824,
			0x08EA8349028949C0,
		};

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
	};
	class pg_enhance :public Singleton<pg_enhance>
	{
	public:
		pg_enhance() {
			ddk::mem_util::init_mem_util();

			UNICODE_STRING procName =
				RTL_CONSTANT_STRING(L"ExAcquireResourceSharedLite");
			const auto realAddress =
				reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&procName));
			
			UNICODE_STRING procName2 =
				RTL_CONSTANT_STRING(L"ExQueueWorkItem");
			const auto realAddress2 =
				reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&procName2));
			g_ExAcquireResourceSharedLite = realAddress;
			g_ExQueueWorkItem = realAddress2;
			info.NumberOfPgContexts = 0;
			m_PgBack = malloc(pg_enhance_data::PG_BACK_SIZE);
			m_PgBack_Pa = MmGetPhysicalAddress(PVOID(m_PgBack));
		}
		~pg_enhance() {
			if (m_PgBack)
			{
				free(m_PgBack);
			}
		}
		bool DisPg() {
			//物理内存扫描
			auto PhysicalMemoryBlock = MmGetPhysicalMemoryRanges();
			auto b_ret = false;
			if (PhysicalMemoryBlock == NULL)
			{
				return b_ret;
			}
			cpu_lock lock;
			lock.lock();
			auto old_irql = KeRaiseIrqlToDpcLevel();


			//小块扫描足够扫出来pgContext，但是win8里偶尔会漏掉一个context，很神奇！
			auto i = 0;

			while (PhysicalMemoryBlock[i].NumberOfBytes.QuadPart != 0)
			{
				PHYSICAL_ADDRESS BaseAddress = PhysicalMemoryBlock[i].BaseAddress;
				LARGE_INTEGER NumberOfBytes = PhysicalMemoryBlock[i].NumberOfBytes;

				//auto VA = MmGetVirtualForPhysical(BaseAddress);
				auto mapped_buffer = MmMapIoSpace(BaseAddress, NumberOfBytes.QuadPart, MmNonCached);
				if (mapped_buffer)
				{
					DisPg(mapped_buffer,nullptr,NumberOfBytes.QuadPart);
					//win7以上版本需要再次爆搜其他patch点
					MmUnmapIoSpace(mapped_buffer, NumberOfBytes.QuadPart);
				}
				while (NumberOfBytes.QuadPart > 0)
				{
					auto MapAddress = MmGetVirtualForPhysical(BaseAddress);
					auto ulAddress = reinterpret_cast<ULONG_PTR>(MapAddress);
					//if (MapAddress)
					{
						auto mapped_buffer = MmMapIoSpace(BaseAddress, PAGE_SIZE, MmNonCached);
						if (mapped_buffer)
						{
							DisPg(mapped_buffer,MapAddress,PAGE_SIZE);
							MmUnmapIoSpace(mapped_buffer, PAGE_SIZE);
							//第二种扫!
							////Win8/win8.1需要考虑跨页问题
							auto next_page = PVOID(ULONG_PTR(MapAddress) + PAGE_SIZE);
							if (MmIsAddressValid(MapAddress)
								&&MmIsAddressValid(next_page)
								&&ddk::mem_util::MmIsAccessibleAddress(MapAddress)
								&&ddk::mem_util::MmIsAccessibleAddress(next_page))
							{
								//LOG_DEBUG("Scan 2 page ok\r\n");
								DisPg(MapAddress, MapAddress, PAGE_SIZE*2);
							}
						}
						else
						{
							LOG_DEBUG("Find a PA %p Could Not Mapping\r\n",PVOID(BaseAddress.QuadPart));
						}
					}
					BaseAddress.QuadPart += PAGE_SIZE;
					NumberOfBytes.QuadPart -= PAGE_SIZE;
				}
				i++;
			}

			if (info.NumberOfPgContexts<1 || info.NumberOfPgContexts>6)
			{
				//must 出问题E!
				b_ret = false;
			}
			else {
				b_ret = true;
				disable_pg_context();
			}
			KeLowerIrql(old_irql);
			lock.unlock();
			if (!b_ret)
			{
				DBG_PRINT("Some Thing is Missing Or Wrong\r\n");
			}
			for (auto k = 0; k < info.NumberOfPgContexts;k++)
			{
				auto result = info.PgContexts[k];
				if (!result.PgContext)
				{
					result.PgContext = ULONG_PTR(MmGetVirtualForPhysical(result.phyAddr));
				}
				if(result.bpatched)
					DBG_PRINT("Patched PatchGuard %p :%p: XorKey %p Size= %p\r\n",
						PVOID(result.PgContext), PVOID(result.phyAddr.QuadPart), PVOID(result.XorKey),PVOID(result.Size));
				else
				{
					DBG_PRINT("Not Patched PatchGuard %p :%p: XorKey %p Size= %p\r\n",
						PVOID(result.PgContext), PVOID(result.phyAddr.QuadPart), PVOID(result.XorKey), PVOID(result.Size));
				}
			}
			if (PhysicalMemoryBlock)
			{
				ExFreePool(PhysicalMemoryBlock);
			}
			return b_ret;
		}
		void DisPg(PVOID Ma,PVOID Va,SIZE_T MemSize)
		{
			//Va是原始地址
			//Ma是可以访问的地址
			auto StartAddress = reinterpret_cast<ULONG_PTR>(Ma);
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
					if (check_pg_context(result))
					{
						//这里不处理掉
						if (Va)
							result.PgContext = (ULONG_PTR)Va + result.PgContext - ULONG_PTR(Ma);
						else
							result.PgContext = 0;
						add_pg_context(result);
					}
				}
			}
		}
	private:
		ULONG_PTR g_ExAcquireResourceSharedLite;
		ULONG_PTR g_ExQueueWorkItem;
		PatchGuardContexts info;
		PVOID m_PgBack;
		PHYSICAL_ADDRESS m_PgBack_Pa;
	private:
		SIZE_T SearchPatchGuardContext(
			__in ULONG_PTR SearchBase,
			__in SIZE_T SearchSize,
			__out PatchGuardContextInfo& Result)
		{
			const auto maxSearchSize =
				SearchSize - sizeof(pg_enhance_data::CmpAppendDllSection_PATTERN);
			for (SIZE_T searchedBytes = 0; searchedBytes < maxSearchSize;
			++searchedBytes)
			{
				const auto addressToBeChecked =
					reinterpret_cast<ULONG64*>(SearchBase + searchedBytes);

				const auto possibleXorKey =
					addressToBeChecked[1] ^ pg_enhance_data::CmpAppendDllSection_PATTERN[1];
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
				sizeof(pg_enhance_data::CmpAppendDllSection_PATTERN) / sizeof(ULONG64);
			C_ASSERT(NUMBER_OF_TIMES_TO_COMPARE == 19);

			for (int i = 2; i < NUMBER_OF_TIMES_TO_COMPARE; ++i)
			{
				const auto decryptedContents = AddressToBeChecked[i] ^ PossibleXorKey;
				if (decryptedContents != pg_enhance_data::CmpAppendDllSection_PATTERN[i])
				{
					return false;
				}
			}
			return true;
		}
	private:
		bool check_pg_context(PatchGuardContextInfo &result)
		{
			__try
			{
				RtlZeroBytes(m_PgBack, pg_enhance_data::PG_BACK_SIZE);
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
						//DBG_PRINT("win10 PgSizeInQowrd = %x\r\n", decryptedPgContext->ContextSizeInQWord);
						//再复制一次
						//RtlCopyMemory(&pgContext[NUMBER_OF_TIMES_TO_DECRYPT], PVOID(result.PgContext + 0xC0),decryptedPgContext->ContextSizeInQWord*8);
						for (auto i = decryptedPgContext->ContextSizeInQWord; i; --i)
						{
							pgContext[i + NUMBER_OF_TIMES_TO_DECRYPT - 1] ^= decryptionKey;
							decryptionKey = _rotr64(decryptionKey, static_cast<UCHAR>(i));
						}
						if (decryptedPgContext->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
						{
							result.Size = decryptedPgContext->ContextSizeInQWord * 8 + 0xC4;
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
						//DBG_PRINT("PgSizeInQowrd = %x\r\n", decryptedPgContext->ContextSizeInQWord);
						for (auto i = decryptedPgContext->ContextSizeInQWord; i; --i)
						{
							pgContext[i + NUMBER_OF_TIMES_TO_DECRYPT - 1] ^= decryptionKey;
							decryptionKey = _rotr64(decryptionKey, static_cast<UCHAR>(i));
						}
						if (decryptedPgContext->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
						{
							result.Size = decryptedPgContext->ContextSizeInQWord * 8 + 0xC4;
							return true;
						}
					}
				}
				else
				{

					if (ddk::util::IsWindows10())
					{
						
						auto pg = reinterpret_cast<PgContextBase10*>(result.PgContext);
						if (!ddk::mem_util::MmIsAccessibleAddress(&pg->ExAcquireResourceSharedLite))
						{
							return false;
						}
						if (pg->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
						{
							result.Size = pg->ContextSizeInQWord * 8 + 0xC4;
							return true;
						}
					}
					else
					{
						auto pg = reinterpret_cast<PgContextBase*>(result.PgContext);
						if (pg->ExAcquireResourceSharedLite == g_ExAcquireResourceSharedLite)
						{
							result.Size = pg->ContextSizeInQWord * 8 + 0xC4;
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
			for (auto i = 0; i < info.NumberOfPgContexts; i++)
			{
				if (info.PgContexts[i].phyAddr.QuadPart == result.phyAddr.QuadPart)
				{
					return;
				}
			}
			result.bpatched = false;
			info.PgContexts[info.NumberOfPgContexts] = result;
			info.NumberOfPgContexts++;
		}
		void disable_pg_context()
		{
			for (auto i = 0; i < info.NumberOfPgContexts;i++)
			{
				auto PgContext = &info.PgContexts[i];
				PgContext->bpatched = false;
				//处理无映射问题！！
				if (PgContext->PgContext == 0)
				{
					PgContext->PgContext = ULONG_PTR(MmGetVirtualForPhysical(PgContext->phyAddr));
				}
				disable_pg_context(PgContext);
			}
		}
		void disable_pg_context(PatchGuardContextInfo * pg)
		{
			if (!MmIsAddressValid(PVOID(pg->PgContext))
				&& !(DWORD64(pg->PgContext)&0xFFFF000000000000))
			{
				return;
			}
			if (pg->XorKey)
			{
				PatchForEncryptedPatchGuardContext(pg);
			}
			else {
				//Win7可以win8 win8.1 win10 pgcontext大小存在一些矛盾！
				PatchForDecryptedPatchGuardContext(pg);
			}
			pg->bpatched = true;
		}
	private:
		void PatchForDecryptedPatchGuardContext(
			__in PatchGuardContextInfo* Info)
		{

			auto pgContext = reinterpret_cast<PgContextBase*>(Info->PgContext);

			if (ddk::util::IsWindows8OrGreater())
			{
				//DBGXXX
				//Win8 win8.1 win10上PG解密状态下，PgContext的size并不包含shellcode的内容，so这是个问题
				//解决方法：找到完整pgcontext大小然后搜索SdbpCheckDll，因为pgcontext其实是开头的部分。
				//先来一个温和的
				auto potential_ExAcquireResourceSharedLite =
					&pgContext->ExAcquireResourceSharedLite;

				static const auto kMaxPointersToOverwrite = 10u;
				for (auto i = 0u; i < kMaxPointersToOverwrite; ++i) {
					if (*potential_ExAcquireResourceSharedLite==g_ExQueueWorkItem)
					{
						*potential_ExAcquireResourceSharedLite = reinterpret_cast<ULONG64>(::FakeExQueueWorkItem);
					}
					++potential_ExAcquireResourceSharedLite;
				}
			}
			else
			{
				// Install hook
				static const auto HEADER_SIZE =
					FIELD_OFFSET(PgContextBase, ExAcquireResourceSharedLite);
				const auto searchSizeInBytes =
					pgContext->ContextSizeInQWord * sizeof(ULONG64) + HEADER_SIZE;

				auto pgSdbpCheckDll = ddk::mem_util::MmMemMem(pgContext, searchSizeInBytes,
					&pg_enhance_data::WINX_SdbpCheckDll_PATTERN[0], sizeof(pg_enhance_data::WINX_SdbpCheckDll_PATTERN));
				ASSERT(pgSdbpCheckDll);

				// Make r13 and r14 zero. These are used as PgContext pointer later, and if
				// values are zero, PatchGuard gracefully ends its activity.
				static const UCHAR PATCH_CODE[] =
				{
					pg_enhance_data::WINX_HOOK_CODE,         // nop or int 3
					0x4D, 0x33, 0xED,       // xor     r13, r13
					0x4D, 0x33, 0xF6,       // xor     r14, r14
					0xc3,                   // ret
				};
				ddk::mem_util::MmForceMemCpy(pgSdbpCheckDll, PATCH_CODE, sizeof(PATCH_CODE));
			}
			// Also, install hook at CmpAppendDllSection because it may be called at
			// the next time as we disabled SdbpCheckDll.
			pgContext->CmpAppendDllSection[pg_enhance_data::WINX_HOOK_OFFSET + 0] = pg_enhance_data::WINX_HOOK_CODE;
			pgContext->CmpAppendDllSection[pg_enhance_data::WINX_HOOK_OFFSET + 1] = 0xc3;   // RET
		}
	private:
		void PatchForEncryptedPatchGuardContext(
			__in PatchGuardContextInfo* Info)
		{
			auto pgContext = DecryptPatchGuardContext(Info);
			pgContext->CmpAppendDllSection[pg_enhance_data::WINX_HOOK_OFFSET + 0] = pg_enhance_data::WINX_HOOK_CODE;
			pgContext->CmpAppendDllSection[pg_enhance_data::WINX_HOOK_OFFSET + 1] = 0xc3;   // RET
			EncryptPatchGuardContext(Info, pgContext);
		}
		PgContextBase* DecryptPatchGuardContext(
			__in PatchGuardContextInfo* Info)
		{
			auto pgContext = reinterpret_cast<ULONG64*>(Info->PgContext);
			static const auto NUMBER_OF_TIMES_TO_DECRYPT =
				FIELD_OFFSET(PgContextBase, ExAcquireResourceSharedLite)
				/ sizeof(ULONG64);
			C_ASSERT(NUMBER_OF_TIMES_TO_DECRYPT == 0x19);
			for (SIZE_T i = 0; i < NUMBER_OF_TIMES_TO_DECRYPT; ++i)
			{
				pgContext[i] ^= Info->XorKey;
			}

			auto decryptionKey = Info->XorKey;
			auto decryptedPgContext = reinterpret_cast<PgContextBase*>(pgContext);
			for (auto i = decryptedPgContext->ContextSizeInQWord; i; --i)
			{
				pgContext[i + NUMBER_OF_TIMES_TO_DECRYPT - 1] ^= decryptionKey;
				decryptionKey = _rotr64(decryptionKey, static_cast<UCHAR>(i));
			}

			return decryptedPgContext;
		}
		void EncryptPatchGuardContext(
			__in PatchGuardContextInfo* Info,
			__in PgContextBase* DecryptedPgContext)
		{
			const auto pgContextSize = DecryptedPgContext->ContextSizeInQWord;
			auto pgContext = reinterpret_cast<ULONG64*>(Info->PgContext);
			static const auto NUMBER_OF_TIMES_TO_ENCRYPT =
				FIELD_OFFSET(PgContextBase, ExAcquireResourceSharedLite)
				/ sizeof(ULONG64);
			C_ASSERT(NUMBER_OF_TIMES_TO_ENCRYPT == 0x19);
			for (SIZE_T i = 0; i < NUMBER_OF_TIMES_TO_ENCRYPT; ++i)
			{
				pgContext[i] ^= Info->XorKey;
			}

			auto decryptionKey = Info->XorKey;
			for (auto i = pgContextSize; i; --i)
			{
				pgContext[i + NUMBER_OF_TIMES_TO_ENCRYPT - 1] ^= decryptionKey;
				decryptionKey = _rotr64(decryptionKey, static_cast<UCHAR>(i));
			}
		}
	};
};