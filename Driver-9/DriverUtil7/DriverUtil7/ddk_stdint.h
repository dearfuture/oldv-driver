#pragma once
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

typedef signed char int_least8_t;
typedef short int_least16_t;
typedef int int_least32_t;

typedef unsigned char uint_least8_t;
typedef unsigned short uint_least16_t;
typedef unsigned int uint_least32_t;

typedef char int_fast8_t;
typedef int int_fast16_t;
typedef int int_fast32_t;

typedef unsigned char uint_fast8_t;
typedef unsigned int uint_fast16_t;
typedef unsigned int uint_fast32_t;

#ifndef _INTPTR_T_DEFINED
#define _INTPTR_T_DEFINED
#ifdef _AMD64_
typedef __int64 intptr_t;
#else /* _WIN64 */
typedef _W64 int intptr_t;
#endif /* _WIN64 */
#endif /* _INTPTR_T_DEFINED */

#ifndef _UINTPTR_T_DEFINED
#define _UINTPTR_T_DEFINED
#ifdef _AMD64_
typedef unsigned __int64 uintptr_t;
#else /* _WIN64 */
typedef _W64 unsigned int uintptr_t;
#endif /* _WIN64 */
#endif /* _UINTPTR_T_DEFINED */

typedef LONGLONG int64_t;
typedef ULONGLONG uint64_t;

typedef LONGLONG int_least64_t;
typedef ULONGLONG uint_least64_t;

typedef LONGLONG int_fast64_t;
typedef ULONGLONG uint_fast64_t;

typedef LONGLONG intmax_t;
typedef ULONGLONG uintmax_t;

typedef unsigned int uint32;
typedef int int32;

typedef unsigned short uint16;
typedef short int16;

typedef unsigned char uint8;
typedef char int8;

typedef unsigned long long int uint64;
