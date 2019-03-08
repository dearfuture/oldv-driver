#include "Base.h"
#include "Device.h"
#include "ioctrl.h"
ddk::CDevice device;
void test_util(PUNICODE_STRING RegistryPath);
void test_util_free();
//////////////////////////////////////////////////////////////////////////
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
//////////////////////////////////////////////////////////////////////////
_Use_decl_annotations_
EXTERN_C
void
UnLoad(
	__in PDRIVER_OBJECT driverObject
	)
{
	UNREFERENCED_PARAMETER(driverObject);
	test_util_free();
	return;
}
//////////////////////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////////////////////
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
	test_util(RegistryPath);
	if(device.create_device(L"\\Device\\DeviceTest", L"\\DosDevices\\DeviceTest",true))
		return STATUS_SUCCESS;
	return STATUS_UNSUCCESSFUL;
}

