#include "Base.h"
#include "Utils.h"
//ddk::CNtReg my_reg;
//void threadcall(int a, int b, int c)
//{
//	DBG_PRINT("%d %d %d\r\n", a, b, c);
//}
//void test_util2(PUNICODE_STRING RegistryPath)
//{
//	auto thread = ddk::CThread(std::bind(&threadcall, 1, 2, 43));
//	thread.join();
//	auto thread1 = ddk::CThread(threadcall, 1, 3, 4);
//	thread1.join();
//	auto file = ddk::CNtFile(std::wstring(L"\\??\\C:\\test.log"), ddk::CNtFile::OPEN_IF);
//	file.writeline(std::string("hello world"));
//	file.close();
//	auto file2 = ddk::CNtFile(std::wstring(L"\\??\\C:\\test2.log"), ddk::CNtFile::OPEN_IF);
//	file2.writeline(std::string("hello world"));
//	file2.close();
//	auto file1 = ddk::CNtFile(std::wstring(L"\\??\\C:\\test.log"), ddk::CNtFile::OPEN_IF);
//	std::string str;
//	file1.readline(str);
//	DBG_PRINT("READ %s\r\n", str);
//	DBG_PRINT("size = %lld\r\n", file1.get_file_size());
//	file1.rename(std::wstring(L"\\??\\C:\\test3.log"));
//	file1.close();
//
//	ddk::CNtFile::del_file(std::wstring(L"\\??\\C:\\test2.log"));
//	auto reg = ddk::CNtReg(ddk::CNtReg::DDK_HKEY::HKEY_CURRENT_USER, std::wstring(L"helloworld"));
//	auto reg2 = reg.create_key(std::wstring(L"setting"));
//	auto str2 = std::wstring(L"Hello World");
//	WCHAR str4[MAX_PATH] = { 0 };
//	auto test_value = std::wstring(L"test");
//	reg2.set_value(test_value, REG_SZ, PVOID(str2.c_str()), str2.length() * 2 + 2);
//	auto test_value2 = std::wstring(L"test2");
//	auto str3 = std::string("Hello World");
//	reg2.set_value(test_value2, REG_BINARY, PVOID(str3.c_str()), str3.length() + 1);
//	size_t s = sizeof(str4);
//	reg2.get_value(test_value, REG_SZ, str4, s);
//	DBG_PRINT("value = %ws\r\n", str4);
//	reg2.del_value(std::wstring(L"hhh2"));
//	auto reg3 = reg.create_key(std::wstring(L"set2"));
//	reg3.set_value(test_value, REG_SZ, PVOID(str2.c_str()), str2.length() * 2 + 2);
//	reg3.set_value(test_value2, REG_BINARY, PVOID(str3.c_str()), str3.length() + 1);
//	//reg2.del_key();
//	//XX
//	WCHAR szKey[MAX_PATH] = { 0 };
//	RtlCopyMemory(szKey, RegistryPath->Buffer, RegistryPath->Length);
//	my_reg.open(std::wstring(szKey));
//	my_reg = my_reg.create_key(std::wstring(L"settings"));
//
//	ddk::CNtFile::file_list_type flist;
//	auto listok = ddk::CNtFile::dir_file(std::wstring(L"\\??\\C:\\"), flist);
//	if (listok)
//	{
//		std::for_each(flist.begin(), flist.end(), [&](ddk::CNtFile::file_rec fitem) {
//			if (fitem.file_attr&FILE_ATTRIBUTE_DIRECTORY)
//				DBG_PRINT("dir = %ws\r\n", fitem.file_name.c_str());
//			else
//				DBG_PRINT("file = %ws\r\n", fitem.file_name.c_str());
//		});
//	}
//}
ddk::nt_event p_event;
void thread()
{
	p_event.wait();
	DBG_PRINT("hello event\r\n");
}
void workroutine(int a, int b, int c)
{
	DBG_PRINT("hell a= %d b= %d c = %d\r\n", a, b, c);
}
void workroutine_dpc(int a, int b, int c)
{
	DBG_PRINT("hell a= %d b= %d c = %d cpu = %d\r\n", a, b, c,KeGetCurrentProcessorNumber());
}
void sleep_test()
{
	for (auto i = 0; i < 100;i++)
	{
		ddk::util::sleep(ddk::util::time::milli_seconds(200));
		DBG_PRINT("cc %d\r\n", i);
	}
}
void timer_routine(int a)
{
	DBG_PRINT("hell timer %d\r\n", a);
}
void timer_routine2()
{
	DBG_PRINT("hell timer 2 \r\n");
}
ddk::nt_timer *timer = nullptr;
ddk::nt_timer *timer_always = nullptr;
void test_util(PUNICODE_STRING RegistryPath)
{
	p_event = ddk::nt_event(std::wstring(L"test_event_a"));
	auto th = ddk::CThread(thread);
	th.detach();
	auto sleepth = ddk::CThread(sleep_test);
	sleepth.detach();
	auto work = ddk::work_item(DelayedWorkQueue,workroutine, 123, 33, 22);
	auto dpc_test = ddk::dpc(workroutine_dpc, 1, 3, 34);
	timer = new ddk::nt_timer(0, 3000, timer_routine, 123);
	timer_always = new ddk::nt_timer(ddk::util::time::milli_seconds(1000), 0, timer_routine,3);

	ddk::cpu_lock cp;
	cp.lock();
	DBG_PRINT("another cpu is locked now\r\n");
	cp.unlock();
	std::wstring now;
	ddk::util::time::get_now_time(now);
	DBG_PRINT("now is %ws\r\n", now.c_str());
	for (auto i = 0ul; i < KeQueryActiveProcessorCount(NULL);i++)
	{
		auto cputhread = ddk::CThread(i, workroutine_dpc, 2, 3, 4);
		cputhread.detach();
	}
}

void test_util_free()
{
	if(timer)
		delete timer;
	if (timer_always)
	{
		delete timer_always;
	}
}