#pragma once
#include "Base.h"
#include <string>
#include "Utils.h"
class CHookX64:public ddk::Singleton<CHookX64>
{

public:
	CHookX64();
	~CHookX64();
private:
	using HOOK_PASS = struct
	{
		ULONG_PTR JmpAddress;
		PVOID OldProc;
		PVOID func_address;
		ULONG OldSize;
	};
	using PHOOK_PASS = HOOK_PASS*;
	HOOK_PASS hook_pass[0x100];
	LONG g_hook_pass_count;
	void init_hook_x64();
	PVOID OldInt;
	ddk::nt_mutex m_IdtPortLock;
public:
	PVOID get_routine(ULONG_PTR Number);
	bool hook_function(PVOID target_func, PVOID new_func, PVOID * old_func);
	bool hook_syscall(std::string function, PVOID new_func, PVOID * old_func);
private:
	void unhook(PVOID func, PVOID org_code, size_t code_size);
};
