#pragma once
#include <stddef.h>
#include <stdint.h>
#include "PageInfo.h"
#include <sys/mman.h>
extern size_t PageSize;
inline size_t divide_and_ceil(size_t x, size_t y)
{
	return 1 + ((x - 1) / y);
}

inline void* AlignToPage(void* addr)
{
	return (void*)((uintptr_t)addr & ~(PageSize - 1));
}

inline bool IsPageNotWritable(PageInfo* info)
{
	return (info != nullptr && !(info->prot & PROT_WRITE));
}

inline void TouchRange(void* ptr, size_t n)
{
	char* start = (char*)AlignToPage(ptr);
	for (char* i = start; i <= (char*)ptr + n - 1; i += PageSize)
	{
		char volatile * ptouch;
		if (i < ptr)
			ptouch = (char*)ptr;
		else
			ptouch = i;
		*ptouch = *ptouch;
	}
}