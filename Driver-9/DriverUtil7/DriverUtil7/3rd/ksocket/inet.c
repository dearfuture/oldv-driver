#include <ntddk.h>
#include "ksocket.h"
#include <ntstrsafe.h>
u_long __cdecl inet_addr(const char *name)
{
    struct in_addr addr;

    if (inet_aton(name, &addr))
    {
        return addr.s_addr;
    }
    else
    {
        return INADDR_NONE;
    }
}

int __cdecl inet_aton(const char *name, struct in_addr *addr)
{
    u_int dots, digits;
    u_long byte;

    if(!name || !addr)
    {
        return 0;
    }

    for (dots = 0, digits = 0, byte = 0, addr->s_addr = 0; *name; name++)
    {
        if (*name == '.')
        {
            addr->s_addr += byte << (8 * dots);
            if (++dots > 3 || digits == 0)
            {
                return 0;
            }
            digits = 0;
            byte = 0;
        }
        else
        {
            byte = byte * 10 + (*name - '0');
            if (++digits > 3 || *name < '0' || *name > '9' || byte > 255)
            {
                return 0;
            }
        }
    }

    if (dots != 3 || digits == 0)
    {
        return 0;
    }

    addr->s_addr += byte << (8 * dots);

    return 1;
}

char * __cdecl inet_ntoa(struct in_addr addr)
{
	unsigned char *ucp = (unsigned char *)&addr;
	char buf[4 * sizeof "123"];
	sprintf_s(buf,sizeof(buf),"%d.%d.%d.%d",
			ucp[0] & 0xff,
			ucp[1] & 0xff,
			ucp[2] & 0xff,
			ucp[3] & 0xff);
	char *name = ExAllocatePool(NonPagedPoolNx, sizeof(buf));
	if (name)
	{
		RtlCopyMemory(name, buf, sizeof(buf));
	}
	return name;
}
