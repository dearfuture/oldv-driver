#include "Base.h"
#include "NtFile.h"
#include <vector>


ddk::CNtFile::CNtFile()
{
	init_file();
}


ddk::CNtFile::~CNtFile()
{
	if (h_file)
	{
		ZwClose(h_file);
	}
}

ddk::CNtFile::CNtFile(std::wstring strFile,ddk::CNtFile::OPEN_TYPE type)
{
	init_file();
	switch (type)
	{
	case ddk::CNtFile::OPEN_EXIST:
		open(strFile);
		break;
	case ddk::CNtFile::CREATE_NEW:
		create(strFile);
		break;
	case ddk::CNtFile::OPEN_IF:
		open_if(strFile);
		break;
	default:
		break;
	}
}

bool ddk::CNtFile::open(std::wstring strFile)
{
	UNICODE_STRING usFileName;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&usFileName, strFile.c_str());

	InitializeObjectAttributes(&oa,
		&usFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//内核模式句柄，忽略大小写
												 // windows本身其实可以支持大小写，
												 // 但是基本仅限于对象名称的大小写，
												 // 低版本的文件系统是忽略文件名大小写的。
		NULL,
		NULL
		);//OA的初始化一般都是这样填写的
	IO_STATUS_BLOCK iosb;
	HANDLE temp_handle = 0;
	auto ns = ZwCreateFile(
		&temp_handle,//句柄指针
		GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,//读写访问
		&oa,//OA
		&iosb,//io状态
		NULL,//一般添NULL
		FILE_ATTRIBUTE_NORMAL,//文件属性一般写NORMAL
		FILE_SHARE_READ | FILE_SHARE_WRITE,//文件共享性，
										   // 一般只填写FILE_SHARE_READ就行，
										   // 但是特殊情况下需要写入0x7也就是全共享模式
		FILE_OPEN,//当文件不存在时，返回失败
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,//
															   // 文件非目录性质
															   // 并且文件操作直接写入文件系统（直接写入不会产生缓冲延时问题，但IO占用很多）
		NULL, //EA属性填写NULL，这是文件创建不是驱动设备的交互，所以EA写NULL,EA长度也是0
		0
		);
	if (ns == STATUS_SUCCESS)
	{
		h_file = temp_handle;
		return true;
	}
	return false;
}


bool ddk::CNtFile::create(std::wstring strFile)
{
	UNICODE_STRING usFileName;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&usFileName, strFile.c_str());

	InitializeObjectAttributes(&oa,
		&usFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//内核模式句柄，忽略大小写
												 // windows本身其实可以支持大小写，
												 // 但是基本仅限于对象名称的大小写，
												 // 低版本的文件系统是忽略文件名大小写的。
		NULL,
		NULL
		);//OA的初始化一般都是这样填写的
	IO_STATUS_BLOCK iosb;
	HANDLE temp_handle = 0;
	auto ns = ZwCreateFile(
		&temp_handle,//句柄指针
		GENERIC_READ | GENERIC_WRITE| SYNCHRONIZE,//读写访问
		&oa,//OA
		&iosb,//io状态
		NULL,//一般添NULL
		FILE_ATTRIBUTE_NORMAL,//文件属性一般写NORMAL
		FILE_SHARE_READ | FILE_SHARE_WRITE,//文件共享性，
										   // 一般只填写FILE_SHARE_READ就行，
										   // 但是特殊情况下需要写入0x7也就是全共享模式
		FILE_CREATE,//当文件不存在时，返回失败
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,//
															   // 文件非目录性质
															   // 并且文件操作直接写入文件系统（直接写入不会产生缓冲延时问题，但IO占用很多）
		NULL, //EA属性填写NULL，这是文件创建不是驱动设备的交互，所以EA写NULL,EA长度也是0
		0
		);
	if (ns == STATUS_SUCCESS)
	{
		h_file = temp_handle;
		return true;
	}
	return false;
}


bool ddk::CNtFile::is_file_exist(std::wstring strFile)
{
	OBJECT_ATTRIBUTES				oa = { 0 };
	UNICODE_STRING					usName = { 0 };
	FILE_NETWORK_OPEN_INFORMATION 	info = { 0 };


	RtlInitUnicodeString(&usName, strFile.c_str());
	RtlZeroMemory(&info, sizeof(FILE_NETWORK_OPEN_INFORMATION));

	InitializeObjectAttributes(
		&oa,
		&usName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);
	auto ns = ZwQueryFullAttributesFile(
		&oa,
		&info);
	if (ns== STATUS_SUCCESS)
	{
		return (!(info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY));
	}
	return false;
}


bool ddk::CNtFile::rename(std::wstring newFile)
{
	if (h_file)
	{
		WCHAR szBuffer[MAX_PATH * 3] = { 0 };
		IO_STATUS_BLOCK iosb;
		PFILE_RENAME_INFORMATION pFileRename;
		UNICODE_STRING nsFileName;
		RtlInitUnicodeString(&nsFileName, newFile.c_str());
		pFileRename = (PFILE_RENAME_INFORMATION)szBuffer;
		pFileRename->ReplaceIfExists = TRUE;
		pFileRename->RootDirectory = NULL;
		pFileRename->FileNameLength = nsFileName.Length;
		RtlCopyMemory(pFileRename->FileName, nsFileName.Buffer, pFileRename->FileNameLength);
		auto ns = ZwSetInformationFile(h_file,
			&iosb,
			pFileRename,
			sizeof(FILE_RENAME_INFORMATION) + pFileRename->FileNameLength,
			FileRenameInformation);
		if (NT_SUCCESS(ns))
		{
			return true;
		}
		DBG_PRINT("rename %ws %x\r\n",pFileRename->FileName,ns);
	}
	return false;
}


void ddk::CNtFile::init_file()
{
	file_offset = 0;
	h_file = nullptr;
}


bool ddk::CNtFile::open_if(std::wstring strFile)
{
	UNICODE_STRING usFileName;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&usFileName, strFile.c_str());

	InitializeObjectAttributes(&oa,
		&usFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,//内核模式句柄，忽略大小写
												 // windows本身其实可以支持大小写，
												 // 但是基本仅限于对象名称的大小写，
												 // 低版本的文件系统是忽略文件名大小写的。
		NULL,
		NULL
		);//OA的初始化一般都是这样填写的
	IO_STATUS_BLOCK iosb;
	HANDLE temp_handle = 0;
	auto ns = ZwCreateFile(
		&temp_handle,//句柄指针
		GENERIC_READ | GENERIC_WRITE|SYNCHRONIZE,//读写访问
		&oa,//OA
		&iosb,//io状态
		NULL,//一般添NULL
		FILE_ATTRIBUTE_NORMAL,//文件属性一般写NORMAL
		FILE_SHARE_READ | FILE_SHARE_WRITE,//文件共享性，
										   // 一般只填写FILE_SHARE_READ就行，
										   // 但是特殊情况下需要写入0x7也就是全共享模式
		FILE_OPEN_IF,//当文件不存在时，创建，存在打开
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,//
															   // 文件非目录性质
															   // 并且文件操作直接写入文件系统（直接写入不会产生缓冲延时问题，但IO占用很多）
		NULL, //EA属性填写NULL，这是文件创建不是驱动设备的交互，所以EA写NULL,EA长度也是0
		0
		);
	if (ns == STATUS_SUCCESS)
	{
		h_file = temp_handle;
		return true;
	}
	return false;
}


void ddk::CNtFile::set_file_append()
{
	file_offset = get_file_size();
}


LONGLONG ddk::CNtFile::get_file_size()
{
	if (!h_file)
		return LONGLONG(0);
	FILE_STANDARD_INFORMATION fsi = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	auto ns = ZwQueryInformationFile(h_file,
		&iosb,
		&fsi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (NT_SUCCESS(ns))
	{
		return fsi.EndOfFile.QuadPart;
	}
	return LONGLONG(0);
}


bool ddk::CNtFile::set_file_size(LONGLONG file_size)
{
	if (!h_file)
	{
		return false;
	}
	IO_STATUS_BLOCK iosb;
	FILE_END_OF_FILE_INFORMATION fendinfo;
	fendinfo.EndOfFile.QuadPart = file_size;
	auto ns = ZwSetInformationFile(h_file,
		&iosb,
		&fendinfo,
		sizeof(FILE_END_OF_FILE_INFORMATION),
		FileEndOfFileInformation);
	if (NT_SUCCESS(ns))
	{
		return true;
	}
	return false;
}


bool ddk::CNtFile::is_eof()
{
	if (h_file&&get_file_size()==file_offset)
	{
		return true;
	}
	return false;
}


bool ddk::CNtFile::seek(LONGLONG distance,ddk::CNtFile::SEEK_TYPE type)
{
	if (!h_file)
	{
		return false;
	}
	auto new_offset = file_offset;
	switch (type)
	{
	case ddk::CNtFile::FILE_BEGIN:
		new_offset = distance;
		break;
	case ddk::CNtFile::FILE_END:
		new_offset = get_file_size() + distance;
		break;
	case ddk::CNtFile::CURRENT_OFFSET:
		new_offset = file_offset + distance;
		break;
	default:
		return false;
		break;
	}

	FILE_POSITION_INFORMATION fpinfo;
	IO_STATUS_BLOCK iosb;
	fpinfo.CurrentByteOffset.QuadPart = new_offset;
	auto ns = ZwSetInformationFile(h_file,
		&iosb,
		&fpinfo,
		sizeof(fpinfo),
		FilePositionInformation);
	if (NT_SUCCESS(ns))
	{
		file_offset = new_offset;
		return true;
	}
	return false;
}

bool ddk::CNtFile::read(PVOID outBuffer, size_t out_size, size_t & read_size)
{
	read_size = 0;
	if (!h_file)
	{
		return false;
	}

	IO_STATUS_BLOCK iosb = { 0 };
	NTSTATUS		ns;
	LARGE_INTEGER offset;
	offset.QuadPart = file_offset;
	ns = ZwReadFile(
		h_file,
		NULL,
		NULL,
		NULL,
		&iosb,
		outBuffer,
		(LONG)out_size,
		&offset,
		NULL);
	if (NT_SUCCESS(ns))
	{
		read_size = iosb.Information;
		file_offset += read_size;
		return true;
	}
	return false;
}


bool ddk::CNtFile::write(PVOID in_buffer, size_t in_size, size_t & write_size)
{
	write_size = 0;
	if (!h_file)
	{
		return false;
	}
	NTSTATUS ns;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER offset;
	offset.QuadPart = file_offset;
	ns = ZwWriteFile(h_file,
		NULL,
		NULL,
		NULL,
		&iosb,
		in_buffer,
		in_size,
		&offset,
		NULL);
	if (NT_SUCCESS(ns))
	{
		write_size = iosb.Information;
		if (iosb.Information == in_size)
		{
			file_offset += in_size;
			return true;
		}
	}
	return false;
}




bool ddk::CNtFile::readline(std::string & strline)
{
	auto ret = false;
	strline = std::string("");
	do 
	{
		CHAR nC[2] = { 0 };
		size_t readsize = 0;
		auto b = read(&nC, sizeof(CHAR), readsize);
		if (!b) break;
		if (nC[0]==13||nC[0]==10)
		{
			ret = true;
			break;
		}
		else
		{
			nC[1] = 0;
			if(nC[0]!=0)
				strline += std::string(nC);
		}
	} while (!is_eof());
	return ret;
}


bool ddk::CNtFile::writeline(std::string strline)
{
	auto write_string = strline;
	write_string += std::string("\r\n");
	size_t write_size = 0;
	return write(PVOID(write_string.c_str()), write_string.size(), write_size);
}


void ddk::CNtFile::close()
{
	if(h_file)
		ZwClose(h_file);
	file_offset = 0;
	h_file = nullptr;
}


bool ddk::CNtFile::del_file(std::wstring strFile)
{
	UNICODE_STRING usFileName;
	NTSTATUS ns;
	OBJECT_ATTRIBUTES oa = { 0 };
	RtlInitUnicodeString(&usFileName, strFile.c_str());
	InitializeObjectAttributes(&oa,
		&usFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);
	ns = ZwDeleteFile(&oa);
	if (NT_SUCCESS(ns))
	{
		return true;
	}
	return false;
}


bool ddk::CNtFile::set_file_attr(DWORD dwFileAttributes)
{

	FILE_BASIC_INFORMATION fbi;
	IO_STATUS_BLOCK iosb;
	auto ns = ZwQueryInformationFile(h_file,
		&iosb,
		&fbi,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation);
	if (NT_SUCCESS(ns))
	{
		fbi.FileAttributes = dwFileAttributes;
		ns = ZwSetInformationFile(h_file,
			&iosb,
			&fbi,
			sizeof(FILE_BASIC_INFORMATION),
			FileBasicInformation);
		if (NT_SUCCESS(ns))
		{
			return true;
		}
	}
	return false;
}

bool ddk::CNtFile::dir_file(std::wstring strDir, file_list_type & file_list)
{
	UNICODE_STRING dirname_unicode;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&dirname_unicode, strDir.c_str());
	InitializeObjectAttributes(&oa, &dirname_unicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	IO_STATUS_BLOCK io_status;
	HANDLE handle = nullptr;
#define FILE_SHARE_DIRECTORY (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
	auto status = ZwCreateFile(&handle, FILE_LIST_DIRECTORY,
		&oa, &io_status, NULL, 0, 
		FILE_SHARE_DIRECTORY,
		FILE_OPEN, 
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
		NULL, 0);
	if (!NT_SUCCESS(status))
	{
		return false;
	}
	auto file_exit = std::experimental::make_scope_exit([&] {ZwClose(handle); });
	auto dir_size = 0x10000;
	auto dir_entries_buffer = (FILE_DIRECTORY_INFORMATION*)malloc(dir_size);
	if (!dir_entries_buffer)
	{
		return false;
	}
	auto free_dir = std::experimental::make_scope_exit([&] {free(dir_entries_buffer); });
	auto first_iteration = BOOLEAN(TRUE);
	for (;;)
	{
		IO_STATUS_BLOCK iob = { 0 };
		RtlSecureZeroMemory(dir_entries_buffer, dir_size);
		auto ns = ZwQueryDirectoryFile(handle,
			NULL,
			NULL,
			NULL,
			&iob,
			dir_entries_buffer,
			dir_size,
			FileDirectoryInformation,
			FALSE,
			NULL,
			first_iteration
			);
		if (!NT_SUCCESS(ns))
		{
			break;
		}
		auto entry = dir_entries_buffer;
		for (;;)
		{
			file_rec file;
			wchar_t file_name[MAX_PATH] = { 0 };
			file.file_attr = entry->FileAttributes;
			RtlCopyMemory(file_name, entry->FileName, entry->FileNameLength);
			file.file_name = strDir+std::wstring(file_name);
			//DBG_PRINT("file:%ws\r\n", file_name);
			file_list.push_back(file);
			if (entry->NextEntryOffset == 0)
				break;
			entry = (FILE_DIRECTORY_INFORMATION *)(((char *)entry) + entry->NextEntryOffset);
		}
		first_iteration = FALSE;
	}
	return true;
}