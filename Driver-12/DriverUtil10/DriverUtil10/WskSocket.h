#pragma once
#include "Base.h"
#include <wsk.h>
namespace ddk
{
	namespace WSK_SOCKET
	{
		static const auto SOCKET_ERROR = -1;

		NTSTATUS NTAPI WSKStartup();
		VOID NTAPI WSKCleanup();

		PWSK_SOCKET
			NTAPI
			CreateSocket(
				__in ADDRESS_FAMILY AddressFamily,
				__in USHORT                 SocketType,
				__in ULONG                  Protocol,
				__in ULONG                  Flags
				);

		NTSTATUS
			NTAPI
			CloseSocket(
				__in PWSK_SOCKET WskSocket
				);

		NTSTATUS
			NTAPI
			Connect(
				__in PWSK_SOCKET        WskSocket,
				__in PSOCKADDR          RemoteAddress
				);

		PWSK_SOCKET
			NTAPI
			SocketConnect(
				__in USHORT             SocketType,
				__in ULONG              Protocol,
				__in PSOCKADDR  RemoteAddress,
				__in PSOCKADDR  LocalAddress
				);

		LONG
			NTAPI
			Send(
				__in PWSK_SOCKET        WskSocket,
				__in PVOID                      Buffer,
				__in ULONG                      BufferSize,
				__in ULONG                      Flags
				);

		LONG
			NTAPI
			SendTo(
				__in PWSK_SOCKET        WskSocket,
				__in PVOID                      Buffer,
				__in ULONG                      BufferSize,
				__in_opt PSOCKADDR      RemoteAddress
				);

		LONG
			NTAPI
			Receive(
				__in  PWSK_SOCKET       WskSocket,
				__out PVOID                     Buffer,
				__in  ULONG                     BufferSize,
				__in  ULONG                     Flags
				);

		LONG
			NTAPI
			ReceiveFrom(
				__in  PWSK_SOCKET       WskSocket,
				__out PVOID                     Buffer,
				__in  ULONG                     BufferSize,
				__out_opt PSOCKADDR     RemoteAddress,
				__out_opt PULONG        ControlFlags
				);

		NTSTATUS
			NTAPI
			Bind(
				__in PWSK_SOCKET        WskSocket,
				__in PSOCKADDR          LocalAddress
				);

		PWSK_SOCKET
			NTAPI
			Accept(
				__in PWSK_SOCKET        WskSocket,
				__out_opt PSOCKADDR     LocalAddress,
				__out_opt PSOCKADDR     RemoteAddress
				);

		NTSTATUS NTAPI ResolveName(
			_In_ PUNICODE_STRING NodeName,
			_In_ PUNICODE_STRING ServiceName,
			_In_opt_ PADDRINFOEXW Hints,
			__out PSOCKADDR_IN ResolvedAddress
			);
		NTSTATUS
			NTAPI
			DisConnect(
				_In_ PWSK_SOCKET	WskSocket
				);
	};
};