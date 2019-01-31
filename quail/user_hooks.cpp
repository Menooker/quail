#include <iostream>
#include <thread>
#include "LockFreeHashmap.h"
#include <unistd.h>  
#include <sys/mman.h>  
#include <signal.h>
#include <dlfcn.h>
#include "bypass_mmap.h"
#include <cassert>
#include <pthread.h>
#include <sys/wait.h>
#include "util.h"
#include "BypassAlloactor.h"
#include "PFishHook.h"
#include "HookFunction.h"



size_t PageSize = sysconf(_SC_PAGESIZE);
extern bool init_called;

BypassAlloactor alloactor;

def_name(malloc, void*, size_t);
def_name(mmap, void*, void *, size_t, int, int, int, __off_t);

void* mmap_bypass_safe(void *__addr, size_t __len, int __prot,
	int __flags, int __fd, __off_t __offset)
{
	if (Name_mmap::func_wrapper::old_func)
		return mmap_bypass(__addr, __len, __prot, __flags, __fd,  __offset);
	else
		return mmap(__addr, __len, __prot, __flags, __fd, __offset);
}

char* BypassAlloactor::addr = (char*)mmap_bypass_safe(nullptr, BypassAlloactor::total_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
std::atomic<size_t> BypassAlloactor::cur_len = { 0 };
//char BypassAlloactor::addr[4096 * 3];

quail::LockFreeHashmap<4096, uintptr_t, PageInfo*, BypassAlloactor> page_map;

typedef void* (*ptrmalloc)(size_t __size);
static ptrmalloc old_malloc = NULL;
static thread_local bool MallocBypass = false;
thread_local bool MallocTouch = false;
bool isCaptureAll = false;


void *malloc_bypass(size_t size)
{
	MallocBypass = true;
	void* ret = malloc(size);
	MallocBypass = false;
	return ret;
}

static thread_local PageInfo* returned_pinfo = nullptr;

PageInfo* AllocPageInfo()
{
	if (returned_pinfo)
	{
		auto ret = returned_pinfo;
		returned_pinfo = nullptr;
		return ret;
	}
	return (PageInfo*)alloactor.alloc(sizeof(PageInfo));
}

void FreePageInfo(PageInfo* ptr)
{
	assert(returned_pinfo == nullptr);
	returned_pinfo = ptr;
}





extern "C"
{
	void * quail_malloc (size_t size) {
		if (MallocBypass)
		{
			return CallOld<Name_malloc>(size);
		}
		void* ret = CallOld<Name_malloc>(size);
		//fprintf(stderr, "%p=malloc(%zd)\n", ret,size);
		uintptr_t start_page = (uintptr_t)AlignToPage(ret);
		uintptr_t end_page = (uintptr_t)AlignToPage((char*)ret + size - 1);
		for (uintptr_t i = start_page; i <= end_page; i += PageSize)
		{
			PageInfo* pInfo = new (AllocPageInfo()) PageInfo(PROT_READ | PROT_WRITE, true);
			if (page_map.insert_if_absent(i, pInfo) != nullptr)
			{
				FreePageInfo(pInfo);
			}
			else if (isCaptureAll)
			{
				//if(i >>32  ==0)
				//	fprintf(stderr, "mprotect %p\n", (void*)i);
				mprotect((void*)i, PageSize, PROT_READ);
			}

		}
		return ret;
	};



	thread_local bool flag_bypass_mmap = false;

	void* quail_mmap(void *__addr, size_t __len, int __prot,
		int __flags, int __fd, __off_t __offset)
	{
		if (!init_called ||flag_bypass_mmap || (__flags & MAP_BYPASS))
		{
			return CallOld<Name_mmap>(__addr, __len, __prot, __flags & ~(MAP_BYPASS), __fd, __offset);
		}
		void* ret;
		if ( (__flags & (MAP_ANONYMOUS | MAP_PRIVATE) ) && !(__flags & MAP_STACK))
		{
			int myprot = __prot;
			if (isCaptureAll)
				myprot = myprot & ~(PROT_WRITE);
			ret = CallOld<Name_mmap>(__addr, __len, myprot, __flags, __fd, __offset);
			for (unsigned i = 0; i < divide_and_ceil(__len, PageSize); i++)
			{
				PageInfo* pInfo = new (AllocPageInfo()) PageInfo(__prot, true);
				if (page_map.insert_if_absent((uintptr_t)ret + i * PageSize, pInfo) != nullptr)
				{
					FreePageInfo(pInfo);
				}
				else
				{
					if (((uintptr_t)ret + i * PageSize) >> 32 == 0)
						fprintf(stderr, "mprotect single %p", (char*)ret + i * PageSize);
				}
			}
		}
		else
		{
			ret = CallOld<Name_mmap>(__addr, __len, __prot, __flags, __fd, __offset);
		}
		//fprintf(stderr, "%p=mmap(%zd)\n", ret, __len);
		return ret;
	}

	void quail_hook_mem_alloc_funcs()
	{
		DoHook<Name_malloc>(quail_malloc);
		DoHook<Name_mmap>(quail_mmap);
	}
}