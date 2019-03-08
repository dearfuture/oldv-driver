#pragma once
namespace ddk {
	namespace util
	{
		static NTSTATUS UtilLoadPointerVaule(const wchar_t *Key, const wchar_t *Value, void **Data)
		{
			PAGED_CODE();

			UNICODE_STRING path = {};
			RtlInitUnicodeString(&path, Key);
			OBJECT_ATTRIBUTES oa = RTL_INIT_OBJECT_ATTRIBUTES(
				&path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

			// Open the registry
			HANDLE keyNaked = nullptr;
			auto status = ZwOpenKey(&keyNaked, KEY_READ, &oa);
			if (!NT_SUCCESS(status)) {
				return status;
			}
			auto key =
				std::experimental::make_unique_resource(std::move(keyNaked), &::ZwClose);

			UNICODE_STRING valueName = {};
			RtlInitUnicodeString(&valueName, Value);

			// Read value
			ULONG resultLength = 0;
			UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(void *)] = {};
			status = ZwQueryValueKey(key.get(), &valueName, KeyValuePartialInformation,
				buffer, sizeof(buffer), &resultLength);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			// Error if it is not an expected type or not a pointer size.
			ULONG expectedRegType = REG_BINARY;
			auto data = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION *>(buffer);
			if (data->Type != expectedRegType || data->DataLength != sizeof(void *)) {
				return STATUS_DATA_NOT_ACCEPTED;
			}

			*Data = *reinterpret_cast<void **>(data->Data);
			return status;
		}
	};
};