#pragma once
#ifndef _NTDDK_
#include <winioctl.h>
#endif
//
// Device type           -- in the "User Defined" range."
//
#define FILEIO_TYPE 40001
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define IOCTL_NONPNP_METHOD_IN_DIRECT \
    CTL_CODE( FILEIO_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS  )

#define IOCTL_NONPNP_METHOD_OUT_DIRECT \
    CTL_CODE( FILEIO_TYPE, 0x901, METHOD_OUT_DIRECT , FILE_ANY_ACCESS  )

#define IOCTL_NONPNP_METHOD_BUFFERED \
    CTL_CODE( FILEIO_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_NONPNP_METHOD_NEITHER \
    CTL_CODE( FILEIO_TYPE, 0x903, METHOD_NEITHER , FILE_ANY_ACCESS  )