#pragma once
extern "C"
{
	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwOpenProcessToken(
			IN HANDLE       ProcessHandle,
			IN ACCESS_MASK  DesiredAccess,
			OUT PHANDLE     TokenHandle
			);
}
