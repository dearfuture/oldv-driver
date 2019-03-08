#pragma once
#include "Base.h"
namespace ddk
{
	namespace filesystem
	{
		bool get_file_object_full_path(PFILE_OBJECT fileobject, PUNICODE_STRING usFullPath)
		{
			bool relate_name = false;
			auto relate_file_object = fileobject->RelatedFileObject;
			auto IsValidUnicodeString = [](PUNICODE_STRING pstr)->decltype(relate_name) {
				bool bRc = false;
				ULONG   ulIndex = 0;
				__try
				{
					if (!MmIsAddressValid(pstr))
						return false;

					if ((NULL == pstr->Buffer) || (0 == pstr->Length))
						return false;

					for (ulIndex = 0; ulIndex < pstr->Length; ulIndex++)
					{
						if (!MmIsAddressValid((UCHAR *)pstr->Buffer + ulIndex))
							return false;
					}

					bRc = true;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					bRc = false;
				}
				return bRc;
			};

			auto is_file_object_name = IsValidUnicodeString(&fileobject->FileName);
			auto is_relate_object_name = relate_file_object ? IsValidUnicodeString(&relate_file_object->FileName) : false;

			if (is_relate_object_name && is_file_object_name)
			{
				if (fileobject->FileName.Buffer[0] != L'\\')
					relate_name = true;
			}
			//if (!KeAreAllApcsDisabled() && //《--ObQueryNameString的崩溃问题，如果Apcs全部Disable下...
			//	// Windows 10: Apcs disabled, Kernel apcs enabled, ObQueryString() does not crash
			//	// Windows 7: Apcs disabled, Kernel apcs disabled (leads to crash if ObQueryNameString() is called)
			if(is_file_object_name)
			{
				NTSTATUS status;
				DEVICE_OBJECT* VolumeDeviceObject = NULL;
				if (fileobject->Vpb != NULL &&
					fileobject->Vpb->RealDevice != NULL) {
					VolumeDeviceObject = fileobject->Vpb->RealDevice;
				}
				else {
					VolumeDeviceObject = fileobject->DeviceObject;
				}
				ULONG ReturnLength = 0;
				status = ObQueryNameString(VolumeDeviceObject, NULL, 0, &ReturnLength);
				if (ReturnLength == 0) {
					return false;
				}
				POBJECT_NAME_INFORMATION NameInfo =
					(POBJECT_NAME_INFORMATION)malloc(ReturnLength);
				if (!NameInfo)
				{
					return false;
				}
				auto free_nameinfo = std::experimental::make_scope_exit([&]() {free(NameInfo); });
				status = ObQueryNameString(VolumeDeviceObject,
					(POBJECT_NAME_INFORMATION)NameInfo,
					ReturnLength,
					&ReturnLength);
				if (NT_SUCCESS(status))
				{
					//\Device\HarddiskVolume2\Windows\System32\notepad.exe
					UNICODE_STRING* usDriverName = &NameInfo->Name;
					UNICODE_STRING usSymbolName = { 0 };
					WCHAR SymbolBuffer[16] = { L"\\??\\X:" };
					RtlInitUnicodeString(&usSymbolName, SymbolBuffer);
					for (WCHAR c = L'A'; c < (L'Z' + 1); ++c)
					{
						usSymbolName.Buffer[wcslen(L"\\??\\")] = c;
						OBJECT_ATTRIBUTES oa;
						InitializeObjectAttributes(
							&oa,
							&usSymbolName,
							OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
							NULL, NULL);

						HANDLE hSymbol;
						status = ZwOpenSymbolicLinkObject(
							&hSymbol,
							GENERIC_READ,
							&oa);

						if (!NT_SUCCESS(status)) {
							continue;
						}

						WCHAR TargetBuffer[64] = { 0 };
						UNICODE_STRING usTarget = { 0 };
						RtlInitEmptyUnicodeString(&usTarget, TargetBuffer, sizeof(TargetBuffer));

						ULONG ReturnLength;
						status = ZwQuerySymbolicLinkObject(hSymbol, &usTarget, &ReturnLength);

						ZwClose(hSymbol);
						hSymbol = NULL;

						if (NT_SUCCESS(status)) {

							if (0 == RtlCompareUnicodeString(usDriverName, &usTarget, FALSE)) {

								RtlCopyUnicodeString(usFullPath, &usSymbolName);
								if (relate_name)
								{
									if (relate_file_object->FileName.Buffer[0] != L'\\'
										&& (L'\0' != relate_file_object->FileName.Buffer[0]))
									{
										RtlAppendUnicodeToString(usFullPath, L"\\");
									}
									RtlAppendUnicodeStringToString(usFullPath, &relate_file_object->FileName);
								}
								if (fileobject->FileName.Buffer[0] != L'\\'
									&&fileobject->FileName.Buffer[0] != L'\0')
								{
									RtlAppendUnicodeToString(usFullPath, L"\\");
								}
								RtlAppendUnicodeStringToString(usFullPath, &fileobject->FileName);
								return true;
							}
						}
					}
				}
			}
			return false;
		}
	};
};