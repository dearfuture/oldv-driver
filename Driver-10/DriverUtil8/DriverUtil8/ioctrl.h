#pragma once
#ifndef _NTDDK_
#include <winioctl.h>
#endif

static const auto DRV_DEVICE_CODE = 0x8000ul;
static const auto DRV_IOCTL_HELLO = CTL_CODE(DRV_DEVICE_CODE, 0x0800, /* 0x0800-0x0FFF */METHOD_BUFFERED, FILE_ANY_ACCESS);
static const auto DRV_IOCTL_HELLO2 = CTL_CODE(DRV_DEVICE_CODE, 0x0801, /* 0x0800-0x0FFF */METHOD_BUFFERED, FILE_ANY_ACCESS);


