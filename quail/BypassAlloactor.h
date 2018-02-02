#pragma once
#include <atomic>
#include <sys/unistd.h>
#include <cassert>
#include <stdio.h>
struct BypassAlloactor
{
	static char* addr;
	static std::atomic<size_t> cur_len;
	static const size_t total_len = 4096 * 1024;
	void* alloc(size_t size)
	{
		assert(cur_len + size < total_len);
		size_t ret = cur_len.fetch_add(size);
		return addr + ret;
	}

	void release(void* ptr, size_t size)
	{
		fprintf(stderr, "Free called but not implemented.\n");
	}
};