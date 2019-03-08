#include "Base.h"
#include "Device.h"
#include "ioctrl.h"
#include "Thread.h"
#include "NtFile.h"
#include "NtReg.h"
#include <algorithm>
ddk::CDevice device;
ddk::CNtReg my_reg;
//_Use_decl_annotations_
//void test_cpp()
//{
//	std::map<DWORD, DWORD>mp;
//	mp[0x0] = 11;
//	DbgPrint("hello world");
//
//	std::map<DWORD, DWORD> y;
//	y[0] = 1;
//	y[12] = 3;
//
//	std::vector<std::string> z;
//	std::string name = std::string("ABCDEFGHIJKLMN");
//	//巨大的array是直接占用Stack的空间
//	std::mt19937 gen(__COUNTER__);
//	std::array<unsigned int, std::mt19937::state_size> seed_data;
//	std::generate_n(seed_data.begin(), seed_data.size(), std::ref(gen));
//	std::seed_seq seq(std::begin(seed_data), std::end(seed_data));
//
//	//OS::PEPROCESS Process = (OS::PEPROCESS)IoGetCurrentProcess();
//
//	//DbgPrint("cur %s\r\n", Process->ImageFileName);
//
//	//OS::KTHREAD
//
//	//std::mt19937 engine(seq);直接吃掉0x2000的Stack空间,直接Stack冒泡蓝屏
//	//所以还是必须用神奇的make_shared大法~
//	auto engine = std::make_shared<std::mt19937>(seq);
//
//	std::transform(name.begin(), name.end(), name.begin(), ::tolower);
//
//	DbgPrint(name.c_str());
//	std::shuffle(name.begin(), name.end(), *engine);
//
//	DbgPrint(name.c_str());
//
//
//	z.push_back(std::string("hello world\r\n"));
//	for (auto a : z)
//	{
//		DbgPrint(a.c_str());
//	}
//
//	DbgPrint("Map\r\n");
//	for (auto a : y)
//	{
//		DbgPrint("%d %x\r\n", a.first, a.second);
//	}
//
//	//Test();//std::bind测试，std::function测试,thread测试
//
//	DbgPrint("tuple\r\n");
//	auto x = std::make_tuple(1, 2, 3);
//
//	DbgPrint("%d\r\n", std::get<0>(x));
//}

_Use_decl_annotations_
EXTERN_C
void
UnLoad(
	__in PDRIVER_OBJECT driverObject
	)
{
	UNREFERENCED_PARAMETER(driverObject);
	return;
}
NTSTATUS Ioctrl_Handle1(PVOID InputBuffer,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	ULONG_PTR *ReturnSize)
{
	DbgPrint("hello world");
	*ReturnSize = 0;
	return STATUS_SUCCESS;
}
NTSTATUS Ioctrl_Handle2(int xxx,
	PVOID InputBuffer,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	ULONG_PTR *ReturnSize)
{
	DbgPrint("hello world %x\r\n",xxx);
	*ReturnSize = 0;
	return STATUS_SUCCESS;
}
void threadcall(int a, int b, int c)
{
	DBG_PRINT("%d %d %d\r\n", a, b, c);
}
_Use_decl_annotations_
EXTERN_C
NTSTATUS
MainDriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);
	//DriverObject->DriverUnload = nullptr;
	device.set_device_code(DRV_DEVICE_CODE);
	auto func = std::bind(&Ioctrl_Handle2, 0x12345, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
	device.set_ioctrl_callback(DRV_IOCTL_HELLO, Ioctrl_Handle1);
	device.set_ioctrl_callback(DRV_IOCTL_HELLO2, func);//std::bind也可以！！！！
	device.set_ioctrl_callback(0x110, Ioctrl_Handle1);
	device.set_ioctrl_callback(0x111, func);
	auto thread = ddk::CThread(std::bind(&threadcall, 1, 2, 43));
	thread.join();
	auto thread1 = ddk::CThread(threadcall, 1, 3,4);
	thread1.join();
	auto file = ddk::CNtFile(std::wstring(L"\\??\\C:\\test.log"),ddk::CNtFile::OPEN_IF);
	file.writeline(std::string("hello world"));
	file.close();
	auto file2 = ddk::CNtFile(std::wstring(L"\\??\\C:\\test2.log"), ddk::CNtFile::OPEN_IF);
	file2.writeline(std::string("hello world"));
	file2.close();
	auto file1 = ddk::CNtFile(std::wstring(L"\\??\\C:\\test.log"), ddk::CNtFile::OPEN_IF);
	std::string str;
	file1.readline(str);
	DBG_PRINT("READ %s\r\n", str);
	DBG_PRINT("size = %lld\r\n", file1.get_file_size());
	file1.rename(std::wstring(L"\\??\\C:\\test3.log"));
	file1.close();

	ddk::CNtFile::del_file(std::wstring(L"\\??\\C:\\test2.log"));
	auto reg = ddk::CNtReg(ddk::CNtReg::DDK_HKEY::HKEY_CURRENT_USER, std::wstring(L"helloworld"));
	auto reg2 = reg.create_key(std::wstring(L"setting"));
	auto str2 = std::wstring(L"Hello World");
	WCHAR str4[MAX_PATH] = { 0 };
	auto test_value = std::wstring(L"test");
	reg2.set_value(test_value, REG_SZ,PVOID(str2.c_str()), str2.length()*2 + 2);
	auto test_value2 = std::wstring(L"test2");
	auto str3 = std::string("Hello World");
	reg2.set_value(test_value2, REG_BINARY, PVOID(str3.c_str()),str3.length()+1);
	size_t s = sizeof(str4);
	reg2.get_value(test_value, REG_SZ, str4, s);
	DBG_PRINT("value = %ws\r\n", str4);
	reg2.del_value(std::wstring(L"hhh2"));
	auto reg3 = reg.create_key(std::wstring(L"set2"));
	reg3.set_value(test_value, REG_SZ, PVOID(str2.c_str()), str2.length() * 2 + 2);
	reg3.set_value(test_value2, REG_BINARY, PVOID(str3.c_str()), str3.length() + 1);
	//reg2.del_key();
	//XX
	WCHAR szKey[MAX_PATH] = { 0 };
	RtlCopyMemory(szKey, RegistryPath->Buffer, RegistryPath->Length);
	my_reg.open(std::wstring(szKey));
	my_reg = my_reg.create_key(std::wstring(L"settings"));

	ddk::CNtFile::file_list_type flist;
	auto listok= ddk::CNtFile::dir_file(std::wstring(L"\\??\\C:\\"), flist);
	if (listok)
	{
		std::for_each(flist.begin(),flist.end(),[&](ddk::CNtFile::file_rec fitem){
			if(fitem.file_attr&FILE_ATTRIBUTE_DIRECTORY)
				DBG_PRINT("dir = %ws\r\n", fitem.file_name.c_str());
			else
				DBG_PRINT("file = %ws\r\n", fitem.file_name.c_str());
		});
	}
	if(device.create_device(L"\\Device\\DeviceTest", L"\\DosDevices\\DeviceTest",true))
		return STATUS_SUCCESS;
	return STATUS_UNSUCCESSFUL;
}

