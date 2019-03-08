#include <ntddk.h>
#include <tdikrnl.h>
#include "ktdi.h"
#include "ksocket.h"

typedef struct _STREAM_SOCKET {
    HANDLE              connectionHandle;
    PFILE_OBJECT        connectionFileObject;
    KEVENT              disconnectEvent;
} STREAM_SOCKET, *PSTREAM_SOCKET;

typedef struct _SOCKET {
    int                 type;
    BOOLEAN             isBound;
    BOOLEAN             isConnected;
    BOOLEAN             isListening;
    BOOLEAN             isShuttingdown;
    BOOLEAN             isShared;
    HANDLE              addressHandle;
    PFILE_OBJECT        addressFileObject;
    PSTREAM_SOCKET      streamSocket;
    struct sockaddr     peer;
} SOCKET, *PSOCKET;

NTSTATUS event_disconnect(PVOID TdiEventContext, CONNECTION_CONTEXT ConnectionContext, LONG DisconnectDataLength,
                          PVOID DisconnectData, LONG DisconnectInformationLength, PVOID DisconnectInformation,
                          ULONG DisconnectFlags)
{
	UNREFERENCED_PARAMETER(DisconnectFlags);
	UNREFERENCED_PARAMETER(DisconnectInformation);
	UNREFERENCED_PARAMETER(DisconnectInformationLength);
	UNREFERENCED_PARAMETER(DisconnectData);
	UNREFERENCED_PARAMETER(DisconnectDataLength);

    PSOCKET s = (PSOCKET) TdiEventContext;
    PSTREAM_SOCKET streamSocket = (PSTREAM_SOCKET) ConnectionContext;
    KeSetEvent(&streamSocket->disconnectEvent, 0, FALSE);
    return STATUS_SUCCESS;
}

INT_PTR __cdecl accept(INT_PTR s, struct sockaddr *addr, int *addrlen)
{
    PSOCKET s1 = (PSOCKET) -s, s2;
    struct sockaddr_in* returnAddr = (struct sockaddr_in*) addr;
    UNICODE_STRING devName;
    NTSTATUS status;

    if (!s1->isListening)
    {
        return -1;
    }

    if (s1->type == SOCK_STREAM)
    {
        u_long* sin_addr = 0;
        u_short* sin_port = 0;

        if (addr != NULL && addrlen != NULL && *addrlen >= sizeof(struct sockaddr_in))
        {
            sin_addr = &returnAddr->sin_addr.s_addr;
            sin_port = &returnAddr->sin_port;
            *addrlen = sizeof(struct sockaddr_in);
        }

        status = tdi_listen(
            s1->streamSocket->connectionFileObject,
            sin_addr,
            sin_port
            );

        if (!NT_SUCCESS(status))
        {
            return -1;
        }

        s2 = (PSOCKET) -socket(AF_INET, s1->type, 0);

        if (-(INT_PTR)s2 == -1)
        {
            return -1;
        }

        s2->isBound = TRUE;
        s2->isConnected = TRUE;

        ObReferenceObject(s1->addressFileObject);
        s2->addressFileObject = s1->addressFileObject;
        s2->addressHandle = NULL;

        s2->streamSocket = s1->streamSocket;
        s2->peer = *addr;

        s1->streamSocket = (PSTREAM_SOCKET) ExAllocatePool(NonPagedPool, sizeof(STREAM_SOCKET));

        if (!s1->streamSocket)
        {
            return -1;
        }

        RtlZeroMemory(s1->streamSocket, sizeof(STREAM_SOCKET));
        s1->streamSocket->connectionHandle = (HANDLE) -1;
        KeInitializeEvent(&s1->streamSocket->disconnectEvent, NotificationEvent, FALSE);

        RtlInitUnicodeString(&devName, L"\\Device\\Tcp");

        status = tdi_open_connection_endpoint(
            &devName,
            s1->streamSocket,
            s1->isShared,
            &s1->streamSocket->connectionHandle,
            &s1->streamSocket->connectionFileObject
            );

        if (!NT_SUCCESS(status))
        {
            s1->streamSocket->connectionFileObject = NULL;
            s1->streamSocket->connectionHandle = (HANDLE) -1;
            return -1;
        }

        status = tdi_associate_address(s1->streamSocket->connectionFileObject, s1->addressHandle);

        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(s1->streamSocket->connectionFileObject);
            s1->streamSocket->connectionFileObject = NULL;
            ZwClose(s1->streamSocket->connectionHandle);
            s1->streamSocket->connectionHandle = (HANDLE) -1;
            return -1;
        }

        return -(INT_PTR)s2;
    }
    else
    {
        return -1;
    }
}

int __cdecl bind(INT_PTR socket, const struct sockaddr *addr, int addrlen)
{
    PSOCKET s = (PSOCKET) -socket;
    const struct sockaddr_in* localAddr = (const struct sockaddr_in*) addr;
    UNICODE_STRING devName;
    NTSTATUS status;

    if (s->isBound || addr == NULL || addrlen < sizeof(struct sockaddr_in))
    {
        return -1;
    }

    if (s->type == SOCK_DGRAM)
    {
        RtlInitUnicodeString(&devName, L"\\Device\\Udp");
    }
    else if (s->type == SOCK_STREAM)
    {
        RtlInitUnicodeString(&devName, L"\\Device\\Tcp");
    }
    else
    {
        return -1;
    }

    status = tdi_open_transport_address(
        &devName,
        localAddr->sin_addr.s_addr,
        localAddr->sin_port,
        s->isShared,
        &s->addressHandle,
        &s->addressFileObject
        );

    if (!NT_SUCCESS(status))
    {
        s->addressFileObject = NULL;
        s->addressHandle = (HANDLE) -1;
        return status;
    }

    if (s->type == SOCK_STREAM)
    {
        tdi_set_event_handler(s->addressFileObject, TDI_EVENT_DISCONNECT, event_disconnect, (PVOID)s);
    }

    s->isBound = TRUE;

    return 0;
}

int __cdecl close(INT_PTR socket)
{
    PSOCKET s = (PSOCKET) -socket;

    if (s->isBound)
    {
        if (s->type == SOCK_STREAM && s->streamSocket)
        {
            if (s->isConnected)
            {
                if (!s->isShuttingdown)
                {
                    tdi_disconnect(s->streamSocket->connectionFileObject, TDI_DISCONNECT_RELEASE);
                }
                KeWaitForSingleObject(&s->streamSocket->disconnectEvent, Executive, KernelMode, FALSE, NULL);
            }
            if (s->streamSocket->connectionFileObject)
            {
                tdi_disassociate_address(s->streamSocket->connectionFileObject);
                ObDereferenceObject(s->streamSocket->connectionFileObject);
            }
            if (s->streamSocket->connectionHandle != (HANDLE) -1)
            {
                ZwClose(s->streamSocket->connectionHandle);
            }
            ExFreePool(s->streamSocket);
        }

        if (s->type == SOCK_DGRAM || s->type == SOCK_STREAM)
        {
            ObDereferenceObject(s->addressFileObject);
            if (s->addressHandle != (HANDLE) -1)
            {
                ZwClose(s->addressHandle);
            }
        }
    }

    ExFreePool(s);

    return 0;
}

int __cdecl connect(INT_PTR socket, const struct sockaddr *addr, int addrlen)
{
    PSOCKET s = (PSOCKET) -socket;
    const struct sockaddr_in* remoteAddr = (const struct sockaddr_in*) addr;
    UNICODE_STRING devName;
    NTSTATUS status;

    if (addr == NULL || addrlen < sizeof(struct sockaddr_in))
    {
        return -1;
    }

    if (!s->isBound)
    {
        struct sockaddr_in localAddr;

        localAddr.sin_family = AF_INET;
        localAddr.sin_port = 0;
        localAddr.sin_addr.s_addr = INADDR_ANY;

        status = bind(socket, (struct sockaddr*) &localAddr, sizeof(localAddr));

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    if (s->type == SOCK_STREAM)
    {
        if (s->isConnected || s->isListening)
        {
            return -1;
        }

        if (!s->streamSocket)
        {
            s->streamSocket = (PSTREAM_SOCKET) ExAllocatePool(NonPagedPool, sizeof(STREAM_SOCKET));

            if (!s->streamSocket)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlZeroMemory(s->streamSocket, sizeof(STREAM_SOCKET));
            s->streamSocket->connectionHandle = (HANDLE) -1;
            KeInitializeEvent(&s->streamSocket->disconnectEvent, NotificationEvent, FALSE);
        }

        RtlInitUnicodeString(&devName, L"\\Device\\Tcp");

        status = tdi_open_connection_endpoint(
            &devName,
            s->streamSocket,
            s->isShared,
            &s->streamSocket->connectionHandle,
            &s->streamSocket->connectionFileObject
            );

        if (!NT_SUCCESS(status))
        {
            s->streamSocket->connectionFileObject = NULL;
            s->streamSocket->connectionHandle = (HANDLE) -1;
            return status;
        }

        status = tdi_associate_address(s->streamSocket->connectionFileObject, s->addressHandle);

        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(s->streamSocket->connectionFileObject);
            s->streamSocket->connectionFileObject = NULL;
            ZwClose(s->streamSocket->connectionHandle);
            s->streamSocket->connectionHandle = (HANDLE) -1;
            return status;
        }

        status = tdi_connect(
            s->streamSocket->connectionFileObject,
            remoteAddr->sin_addr.s_addr,
            remoteAddr->sin_port
            );

        if (!NT_SUCCESS(status))
        {
            tdi_disassociate_address(s->streamSocket->connectionFileObject);
            ObDereferenceObject(s->streamSocket->connectionFileObject);
            s->streamSocket->connectionFileObject = NULL;
            ZwClose(s->streamSocket->connectionHandle);
            s->streamSocket->connectionHandle = (HANDLE) -1;
            return status;
        }
        else
        {
            s->peer = *addr;
            s->isConnected = TRUE;
            return 0;
        }
    }
    else if (s->type == SOCK_DGRAM)
    {
        s->peer = *addr;
        if (remoteAddr->sin_addr.s_addr == 0 && remoteAddr->sin_port == 0)
        {
            s->isConnected = FALSE;
        }
        else
        {
            s->isConnected = TRUE;
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

int __cdecl getpeername(INT_PTR socket, struct sockaddr *addr, int *addrlen)
{
    PSOCKET s = (PSOCKET) -socket;

    if (!s->isConnected || addr == NULL || addrlen == NULL || *addrlen < sizeof(struct sockaddr_in))
    {
        return -1;
    }

    *addr = s->peer;
    *addrlen = sizeof(s->peer);

    return 0;
}

int __cdecl getsockname(INT_PTR socket, struct sockaddr *addr, int *addrlen)
{
    PSOCKET s = (PSOCKET) -socket;
    struct sockaddr_in* localAddr = (struct sockaddr_in*) addr;

    if (!s->isBound || addr == NULL || addrlen == NULL || *addrlen < sizeof(struct sockaddr_in))
    {
        return -1;
    }

    if (s->type == SOCK_DGRAM)
    {
        *addrlen = sizeof(struct sockaddr_in);

        return tdi_query_address(
            s->addressFileObject,
            &localAddr->sin_addr.s_addr,
            &localAddr->sin_port
            );
    }
    else if (s->type == SOCK_STREAM)
    {
        *addrlen = sizeof(struct sockaddr_in);

        return tdi_query_address(
            s->streamSocket && s->streamSocket->connectionFileObject ? s->streamSocket->connectionFileObject : s->addressFileObject,
            &localAddr->sin_addr.s_addr,
            &localAddr->sin_port
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl getsockopt(INT_PTR socket, int level, int optname, char *optval, int *optlen)
{
	UNREFERENCED_PARAMETER(socket);
	UNREFERENCED_PARAMETER(level);
	UNREFERENCED_PARAMETER(optname);
	UNREFERENCED_PARAMETER(optval);
	UNREFERENCED_PARAMETER(optlen);
    return -1;
}

int __cdecl listen(INT_PTR socket, int backlog)
{
	UNREFERENCED_PARAMETER(backlog);

    PSOCKET s = (PSOCKET) -socket;
    UNICODE_STRING devName;
    NTSTATUS status;

    if (!s->isBound || s->isConnected)
    {
        return -1;
    }

    if (s->type == SOCK_STREAM)
    {
        if (s->isListening)
        {
            return 0;
        }

        if (!s->streamSocket)
        {
            s->streamSocket = (PSTREAM_SOCKET) ExAllocatePool(NonPagedPool, sizeof(STREAM_SOCKET));

            if (!s->streamSocket)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlZeroMemory(s->streamSocket, sizeof(STREAM_SOCKET));
            s->streamSocket->connectionHandle = (HANDLE) -1;
            KeInitializeEvent(&s->streamSocket->disconnectEvent, NotificationEvent, FALSE);
        }

        RtlInitUnicodeString(&devName, L"\\Device\\Tcp");

        status = tdi_open_connection_endpoint(
            &devName,
            s->streamSocket,
            s->isShared,
            &s->streamSocket->connectionHandle,
            &s->streamSocket->connectionFileObject
            );

        if (!NT_SUCCESS(status))
        {
            s->streamSocket->connectionFileObject = NULL;
            s->streamSocket->connectionHandle = (HANDLE) -1;
            return status;
        }

        status = tdi_associate_address(s->streamSocket->connectionFileObject, s->addressHandle);

        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(s->streamSocket->connectionFileObject);
            s->streamSocket->connectionFileObject = NULL;
            ZwClose(s->streamSocket->connectionHandle);
            s->streamSocket->connectionHandle = (HANDLE) -1;
            return status;
        }

        s->isListening = TRUE;

        return 0;
    }
    else
    {
        return -1;
    }
}

int __cdecl recv(INT_PTR socket, char *buf, int len, int flags)
{
    PSOCKET s = (PSOCKET) -socket;

    if (s->type == SOCK_DGRAM)
    {
        return recvfrom(socket, buf, len, flags, 0, 0);
    }
    else if (s->type == SOCK_STREAM)
    {
        if (!s->isConnected)
        {
            return -1;
        }

        return tdi_recv_stream(
            s->streamSocket->connectionFileObject,
            buf,
            len,
            flags == MSG_OOB ? TDI_RECEIVE_EXPEDITED : TDI_RECEIVE_NORMAL
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl recvfrom(INT_PTR socket, char *buf, int len, int flags, struct sockaddr *addr, int *addrlen)
{
    PSOCKET s = (PSOCKET) -socket;
    struct sockaddr_in* returnAddr = (struct sockaddr_in*) addr;

    if (s->type == SOCK_STREAM)
    {
        return recv(socket, buf, len, flags);
    }
    else if (s->type == SOCK_DGRAM)
    {
        u_long* sin_addr = 0;
        u_short* sin_port = 0;

        if (!s->isBound)
        {
            return -1;
        }

        if (addr != NULL && addrlen != NULL && *addrlen >= sizeof(struct sockaddr_in))
        {
            sin_addr = &returnAddr->sin_addr.s_addr;
            sin_port = &returnAddr->sin_port;
            *addrlen = sizeof(struct sockaddr_in);
        }

        return tdi_recv_dgram(
            s->addressFileObject,
            sin_addr,
            sin_port,
            buf,
            len,
            TDI_RECEIVE_NORMAL
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout)
{
	UNREFERENCED_PARAMETER(nfds);
	UNREFERENCED_PARAMETER(readfds);
	UNREFERENCED_PARAMETER(writefds);
	UNREFERENCED_PARAMETER(exceptfds);
	UNREFERENCED_PARAMETER(timeout);

    return -1;
}

int __cdecl send(INT_PTR socket, const char *buf, int len, int flags)
{
    PSOCKET s = (PSOCKET) -socket;

    if (!s->isConnected)
    {
        return -1;
    }

    if (s->type == SOCK_DGRAM)
    {
        return sendto(socket, buf, len, flags, &s->peer, sizeof(s->peer));
    }
    else if (s->type == SOCK_STREAM)
    {
        return tdi_send_stream(
            s->streamSocket->connectionFileObject,
            buf,
            len,
            flags == MSG_OOB ? TDI_SEND_EXPEDITED : 0
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl send_mdl(INT_PTR socket, PMDL mdl, int flags)
{
    PSOCKET s = (PSOCKET) -socket;

    if (!s->isConnected)
    {
        return -1;
    }

    if (s->type == SOCK_DGRAM)
    {
        return sendto_mdl(socket, mdl, flags, &s->peer, sizeof(s->peer));
    }
    else if (s->type == SOCK_STREAM)
    {
        return tdi_send_stream_mdl(
            s->streamSocket->connectionFileObject,
            mdl,
            flags == MSG_OOB ? TDI_SEND_EXPEDITED : 0
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl send_mdl_async(INT_PTR socket, PMDL mdl, int flags, void (*completion_routine)(int status, void *context), void *context)
{
    PSOCKET s = (PSOCKET) -socket;

    if (!s->isConnected)
    {
        return -1;
    }

    if (s->type == SOCK_STREAM)
    {
        return tdi_send_stream_mdl_async(
            s->streamSocket->connectionFileObject,
            mdl,
            flags == MSG_OOB ? TDI_SEND_EXPEDITED : 0,
            completion_routine,
            context
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl sendto(INT_PTR socket, const char *buf, int len, int flags, const struct sockaddr *addr, int addrlen)
{
    PSOCKET s = (PSOCKET) -socket;
    const struct sockaddr_in* remoteAddr = (const struct sockaddr_in*) addr;

    if (s->type == SOCK_STREAM)
    {
        return send(socket, buf, len, flags);
    }
    else if (s->type == SOCK_DGRAM)
    {
        if (addr == NULL || addrlen < sizeof(struct sockaddr_in))
        {
            return -1;
        }

        if (!s->isBound)
        {
            struct sockaddr_in localAddr;
            NTSTATUS status;

            localAddr.sin_family = AF_INET;
            localAddr.sin_port = 0;
            localAddr.sin_addr.s_addr = INADDR_ANY;

            status = bind(socket, (struct sockaddr*) &localAddr, sizeof(localAddr));

            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }

        return tdi_send_dgram(
            s->addressFileObject,
            remoteAddr->sin_addr.s_addr,
            remoteAddr->sin_port,
            buf,
            len
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl sendto_mdl(INT_PTR socket, PMDL mdl, int flags, const struct sockaddr *addr, int addrlen)
{
    PSOCKET s = (PSOCKET) -socket;
    const struct sockaddr_in* remoteAddr = (const struct sockaddr_in*) addr;

    if (s->type == SOCK_STREAM)
    {
        return send_mdl(socket, mdl, flags);
    }
    else if (s->type == SOCK_DGRAM)
    {
        if (addr == NULL || addrlen < sizeof(struct sockaddr_in))
        {
            return -1;
        }

        if (!s->isBound)
        {
            struct sockaddr_in localAddr;
            NTSTATUS status;

            localAddr.sin_family = AF_INET;
            localAddr.sin_port = 0;
            localAddr.sin_addr.s_addr = INADDR_ANY;

            status = bind(socket, (struct sockaddr*) &localAddr, sizeof(localAddr));

            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }

        return tdi_send_dgram_mdl(
            s->addressFileObject,
            remoteAddr->sin_addr.s_addr,
            remoteAddr->sin_port,
            mdl
            );
    }
    else
    {
        return -1;
    }
}

int __cdecl setsockopt(INT_PTR socket, int level, int optname, const char *optval, int optlen)
{
	UNREFERENCED_PARAMETER(socket);
	UNREFERENCED_PARAMETER(level);
	UNREFERENCED_PARAMETER(optname);
	UNREFERENCED_PARAMETER(optval);
	UNREFERENCED_PARAMETER(optlen);

    return -1;
}

int __cdecl shutdown(INT_PTR socket, int how)
{
	UNREFERENCED_PARAMETER(how);

    PSOCKET s = (PSOCKET) -socket;

    if (!s->isConnected)
    {
        return -1;
    }

    if (s->type == SOCK_STREAM)
    {
        s->isShuttingdown = TRUE;
        return tdi_disconnect(s->streamSocket->connectionFileObject, TDI_DISCONNECT_RELEASE);
    }
    else
    {
        return -1;
    }
}

INT_PTR __cdecl socket(int af, int type, int protocol)
{
    PSOCKET s;

    if (af != AF_INET ||
       (type != SOCK_DGRAM && type != SOCK_STREAM) ||
       (type == SOCK_DGRAM && protocol != IPPROTO_UDP && protocol != 0) ||
       (type == SOCK_STREAM && protocol != IPPROTO_TCP && protocol != 0)
       )
    {
        return -1;
    }

    s = (PSOCKET) ExAllocatePool(NonPagedPool, sizeof(SOCKET));

    if (!s)
    {
        return -1;
    }

    RtlZeroMemory(s, sizeof(SOCKET));

    s->type = type;
    s->addressHandle = (HANDLE) -1;

    return -(INT_PTR)s;
}
