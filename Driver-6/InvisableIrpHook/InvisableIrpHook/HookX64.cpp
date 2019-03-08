
#include "Base.h"
#include "HookX64.h"
#include "distorm3.hpp"

//////////////////////////////////////////////////////////////////////////
EXTERN_C PVOID DispatchTrap(ULONG_PTR Number);
EXTERN_C VOID Int25Trap();
//////////////////////////////////////////////////////////////////////////
static const LONG HOOK_POOL_TAG = 'hook';
//////////////////////////////////////////////////////////////////////////
CHookX64::CHookX64()
{
	g_hook_pass_count = 0;
	RtlZeroMemory(hook_pass, sizeof(hook_pass));
	init_hook_x64();
}


CHookX64::~CHookX64()
{
	DBG_PRINT("unhook all hooks\r\n");
	//todo::卸载钩子
	for (auto i = 0; i < g_hook_pass_count;i++)
	{
		auto hook = &hook_pass[i];
		unhook(hook->func_address, hook->OldProc, hook->OldSize);
	}
}


void CHookX64::init_hook_x64()
{
	OldInt = nullptr;
	DBG_PRINT("init hook x64\r\n");
	ddk::util::copy_idt(0x3, 0x25);
	ddk::util::hook_idt(0x25, (PVOID)Int25Trap, &OldInt);
}

PVOID CHookX64::get_routine(ULONG_PTR Number)
{
	return reinterpret_cast<PVOID> (hook_pass[Number].JmpAddress);
}


EXTERN_C PVOID DispatchTrap(ULONG_PTR Number)
{
	return CHookX64::getInstance().get_routine(Number);
}



bool CHookX64::hook_function(PVOID target_func, PVOID new_func, PVOID * old_func)
{
	//4字节hook!
	const BYTE CodeHook[] = { 0x6A,0x00,0xCD,0x25 };
	auto jmp_size = 4;
	auto old_code = ExAllocatePoolWithTag(NonPagedPool, jmp_size * 4 + 14 + 0x10, HOOK_POOL_TAG);
	auto exitp = std::experimental::make_scope_exit([&] {ExFreePoolWithTag(old_code, HOOK_POOL_TAG); });
	auto target_code = reinterpret_cast<BYTE*>(old_code);

	if (g_hook_pass_count>=0x100)
	{
		return false;
	}
	m_IdtPortLock.lock();
	hook_pass[g_hook_pass_count].JmpAddress = (ULONG_PTR)new_func;
	m_IdtPortLock.unlock();

	_CodeInfo ci = { 0 };
	ci.code = reinterpret_cast<uint8_t*>(target_func);
	ci.codeOffset = (_OffsetType)target_func;
	ci.codeLen = jmp_size * 3 + 0x10;
#ifdef _X86_
	ci.dt = Decode32Bits;
#else
	ci.dt = Decode64Bits;
#endif
	ci.features = DF_NONE;
	unsigned int InstrSize = 0;
	do
	{
		_DInst dec[1];
		UINT decCnt = 0;
		distorm_decompose(&ci, dec, 1, &decCnt);
		if (dec->flags == FLAG_NOT_DECODABLE)
		{
			return false;
		}
		auto fc = META_GET_FC(dec->meta);
		if (fc == FC_UNC_BRANCH || fc == FC_CND_BRANCH || fc == FC_CALL || fc == FC_INT || fc == FC_RET || fc == FC_SYS)
		{
			//有改变RIP的指令，拒绝继续xx！
			//TODO::处理各类jcc/call的指令迁移
			return false;
		}
		{
			//non branching instruction
			memcpy(target_code, (void*)ci.codeOffset, dec->size);
			target_code += dec->size;
		}
#ifdef _AMD64_

		if (dec->flags & FLAG_RIP_RELATIVE)
		{
			/*auto p_targ = INSTRUCTION_GET_RIP_TARGET(dec);
			_DecodedInst inst;
			distorm_format(&ci, dec, &inst);
			ptrdiff_t diff;
			unsigned int immSize = 0;
			diff = ((ptrdiff_t)p_targ - (ptrdiff_t)(target_code - dec->size));
			for (auto i = 0; i < OPERANDS_NO; i++) {
				if (dec->ops[i].type == O_IMM) {
					immSize = dec->ops[i].size / 8;
					break;
				}
			}
			auto fix_code = target_code - immSize - 4;
			*(unsigned int*)fix_code = (unsigned int)diff;*/
			return false;
		}
#endif	
		ci.codeOffset = ci.nextOffset;
		ci.code += dec->size;
		InstrSize += dec->size;
	} while (int(InstrSize) < jmp_size);

	int OverridenSize = InstrSize;
	//Jump back to source
	{
		ddk::util::write_jmp(reinterpret_cast<PVOID>(target_code),reinterpret_cast<ULONG_PTR>((BYTE*)target_func + InstrSize));
	}
	*old_func = old_code;

	//用MDL去掉内存保护！
	auto pWriteMdl = IoAllocateMdl((PVOID)target_func,
		14,
		FALSE,
		FALSE,
		NULL);
	if (pWriteMdl == NULL)
	{
		return false;
	}
	auto exit_mdl = std::experimental::make_scope_exit([&]() {IoFreeMdl(pWriteMdl); });
	MmBuildMdlForNonPagedPool(pWriteMdl);
	__try
	{
		MmProbeAndLockPages(pWriteMdl, KernelMode, IoModifyAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	exit_mdl.release();
	auto pFunction = (PCHAR)MmMapLockedPages(pWriteMdl, KernelMode);
	if (pFunction == NULL)
	{
		return false;
	}
	auto p_f = std::experimental::make_scope_exit([&]() {
		MmUnmapLockedPages((PVOID)pFunction, pWriteMdl);
		IoFreeMdl(pWriteMdl); });
	//进行hook
	if(1){
		LONG32 Code = 0;
		KIRQL oldirql;

		RtlCopyMemory(&Code, CodeHook, 4);

		m_IdtPortLock.lock();
		((BYTE *)&Code)[1] = (BYTE)g_hook_pass_count;
		m_IdtPortLock.unlock();

		ddk::cpu_lock _cpu;
		_cpu.lock();
		KeRaiseIrql(HIGH_LEVEL, &oldirql);
		InterlockedExchange((LONG*)pFunction, (LONG)Code);
		KeLowerIrql(oldirql);
		_cpu.unlock();
		
	}
	exitp.release();
	m_IdtPortLock.lock();
	hook_pass[g_hook_pass_count].OldProc = old_code;
	hook_pass[g_hook_pass_count].OldSize = OverridenSize;
	hook_pass[g_hook_pass_count].func_address = target_func;
	InterlockedIncrement(&g_hook_pass_count);
	m_IdtPortLock.unlock();
	return true;
}


bool CHookX64::hook_syscall(std::string function, PVOID new_func, PVOID * old_func)
{
	DBG_PRINT("hook syscall begin1\r\n");
	auto syscall = ddk::util::DynImport::Instance().get_proc_address(function);
	DBG_PRINT("hook syscall begin2\r\n");
	if (syscall)
	{
		DBG_PRINT("hook syscall begin3\r\n");
		return hook_function(syscall, new_func, old_func);
	}
	return false;
}


void CHookX64::unhook(PVOID func, PVOID org_code, size_t code_size)
{
	//用MDL去掉内存保护！
	auto pWriteMdl = IoAllocateMdl((PVOID)func,
		code_size,
		FALSE,
		FALSE,
		NULL);
	if (pWriteMdl == NULL)
	{
		return ;
	}
	auto exit_mdl = std::experimental::make_scope_exit([&]() {IoFreeMdl(pWriteMdl); });
	MmBuildMdlForNonPagedPool(pWriteMdl);
	__try
	{
		MmProbeAndLockPages(pWriteMdl, KernelMode, IoModifyAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return ;
	}
	exit_mdl.release();
	auto pFunction = (PCHAR)MmMapLockedPages(pWriteMdl, KernelMode);
	if (pFunction == NULL)
	{
		return ;
	}
	auto p_f = std::experimental::make_scope_exit([&]() {
		MmUnmapLockedPages((PVOID)pFunction, pWriteMdl);
		IoFreeMdl(pWriteMdl); });
	//进行hook
	if (1) {
		KIRQL oldirql;
		ddk::cpu_lock _cpu;
		_cpu.lock();
		KeRaiseIrql(HIGH_LEVEL, &oldirql);
		RtlCopyMemory(pFunction, org_code, code_size);
		KeLowerIrql(oldirql);
		_cpu.unlock();
	}
	return ;
}
