#pragma once
#include "util_version.h"
#pragma warning(disable:4091)
#pragma warning(disable:4200)
#pragma warning(disable:4005)
#pragma warning(disable:4146)
namespace ddk
{
	template<OS_VERSION>
	class ntos;
	namespace ntos_space
	{
		namespace win7x64
		{
			#include "win7_64.h"
		}
		namespace win7sp1x64
		{
			#include "win7_sp1_64.h"
		}
		namespace win8_x64
		{

		}
		namespace win8_1_x64
		{

		}
		namespace win10_10586_x64
		{

		}
		namespace win10_14393_x64
		{

		}
	};
	template<>
	class ntos<WIN7>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win7x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win7x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win7x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win7x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win7x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win7x64::POBJECT_TYPE;
	};

	template<>
	class ntos<WIN7SP1>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win7sp1x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win7sp1x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win7sp1x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win7sp1x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win7sp1x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win7sp1x64::POBJECT_TYPE;
	};
	
	template<>
	class ntos<WIN8>
	{
	public:
		
	};

	template<>
	class ntos<WIN10_10586>
	{
	public:

	};
}