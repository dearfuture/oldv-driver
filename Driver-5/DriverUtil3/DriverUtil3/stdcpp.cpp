#include "Base.h"
#include <memory>
extern "C"
int
__cdecl
atexit(
	__in void(__cdecl *destructor)(void)
	)
{
	if (!destructor)
		return 0;

	ATEXIT_ENTRY* entry = new ATEXIT_ENTRY(destructor, g_pTopAtexitEntry);
	if (!entry)
		return 0;
	g_pTopAtexitEntry = entry;
	return 1;
}

#if defined(_IA64_) || defined(_AMD64_)
#pragma section(".CRT$XCA",long,read)
__declspec(allocate(".CRT$XCA")) void(*__ctors_begin__[1])(void) = { 0 };
#pragma section(".CRT$XCZ",long,read)
__declspec(allocate(".CRT$XCZ")) void(*__ctors_end__[1])(void) = { 0 };
#pragma data_seg()
#else
#pragma data_seg(".CRT$XCA")
void(*__ctors_begin__[1])(void) = { 0 };
#pragma data_seg(".CRT$XCZ")
void(*__ctors_end__[1])(void) = { 0 };
#pragma data_seg()
#endif

#pragma data_seg(".STL$A")
void(*___StlStartInitCalls__[1])(void) = { 0 };
#pragma data_seg(".STL$L")
void(*___StlEndInitCalls__[1])(void) = { 0 };
#pragma data_seg(".STL$M")
void(*___StlStartTerminateCalls__[1])(void) = { 0 };
#pragma data_seg(".STL$Z")
void(*___StlEndTerminateCalls__[1])(void) = { 0 };
#pragma data_seg()

extern "C"
void
__cdecl
cc_doexit(
	__in int,
	__in int,
	__in int
	)
{
	for (ATEXIT_ENTRY* entry = g_pTopAtexitEntry; entry;)
	{
		ATEXIT_ENTRY* next = entry->Next;
		delete entry;
		entry = next;
	}
}

extern "C"
int
__cdecl
cc_init(
	__in int
	)
{
	for (void(**ctor)(void) = __ctors_begin__ + 1;
	*ctor && ctor < __ctors_end__;
		ctor++)
	{
		(*ctor)();
	}
	return 0;
}


#define _LIBC_POOL_TAG 'LIBC'

#pragma pack(push, 1)
struct MEMBLOCK
{
	size_t	size;
#pragma warning(push)               
#pragma warning (disable : 4200)
	char data[0];
#pragma warning(pop)
};
#pragma pack(pop)

#pragma warning(push)               
#pragma warning (disable : 4565)
__drv_maxIRQL(DISPATCH_LEVEL)
void*
__cdecl
malloc(
	__in size_t size
	)
{
	if ((size_t)(~0) - sizeof(MEMBLOCK) < size)
		return nullptr;

	MEMBLOCK* block = static_cast<MEMBLOCK*>(
		ExAllocatePoolWithTag(
			NonPagedPoolNxCacheAligned,
			size + sizeof(MEMBLOCK),
			_LIBC_POOL_TAG));

	if (nullptr == block)
		return nullptr;
	block->size = size;
	return block->data;
}

__drv_maxIRQL(DISPATCH_LEVEL)
void
__cdecl
free(
	__inout void* ptr
	)
{
	if (ptr)
		ExFreePoolWithTag(CONTAINING_RECORD(ptr, MEMBLOCK, data), _LIBC_POOL_TAG);
}

__drv_maxIRQL(DISPATCH_LEVEL)
void*
__cdecl
realloc(
	__in_opt void* ptr,
	__in size_t size
	)
{
	if (!ptr)
		return malloc(size);

	if (CONTAINING_RECORD(ptr, MEMBLOCK, data)->size >= size)
		return ptr;

	auto inblock = std::unique_ptr<unsigned char>(static_cast<unsigned char*>(ptr));

	// alloc new block
	void* mem = malloc(size);
	if (!mem)
		return nullptr;

	// copy from old one, not overflow ..
	memcpy(mem, inblock.get(), size);
	return mem;
}

extern "C"
__drv_maxIRQL(DISPATCH_LEVEL)
void*
__cdecl
calloc(
	__in size_t n,
	__in size_t size
	)
{
	if (!size)
		return nullptr;
	if ((size_t)(~0) / n < size)
		return nullptr;
	size_t total = n * size;

	void* p = malloc(total);

	if (!p)
		return nullptr;

	return memset(p, 0, total);
}
#pragma warning(pop)