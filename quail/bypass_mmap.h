#pragma once
#include <sys/mman.h>
#define MAP_BYPASS 0x10000000
inline void* mmap_bypass(void *__addr, size_t __len, int __prot,
	int __flags, int __fd, __off_t __offset)
{
	return mmap(__addr, __len, __prot, __flags | MAP_BYPASS, __fd, __offset);
}
