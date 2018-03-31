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
#include "HookFunction.h"



size_t PageSize = sysconf(_SC_PAGESIZE);
extern bool init_called;

BypassAlloactor alloactor;
char* BypassAlloactor::addr = (char*)mmap_bypass(nullptr, BypassAlloactor::total_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
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



def_name(malloc);
auto mymalloc = [](size_t size)->void* {
	if (MallocBypass)
	{
		CallOld(Name_malloc(), (void*)(0), size);
	}
	void* ret = CallOld(Name_malloc(), (void*)(0), size);
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

extern "C" void *malloc(size_t size)
{
	return CallHooked(Name_malloc(), mymalloc, (void*)(0), size);
}
/*
extern "C" void *malloc(size_t size)
{
	if (!old_malloc)
	{
		old_malloc = (ptrmalloc)dlsym(RTLD_NEXT, "malloc");
		if (NULL == old_malloc) {
			fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
		}
	}
	if (MallocBypass || !init_called)
	{
		return old_malloc(size);
	}
	
	void* ret = old_malloc(size);
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
	}
	return ret;
}*/





extern "C"
{

	typedef void* (*ptrmmap)(void *__addr, size_t __len, int __prot,
		int __flags, int __fd, __off_t __offset);
	static ptrmmap old_mmap = NULL;
	thread_local bool flag_bypass_mmap = false;

	void* quail_mmap(void *__addr, size_t __len, int __prot,
		int __flags, int __fd, __off_t __offset)
	{
		if (!old_mmap)
		{
			old_mmap = (ptrmmap)dlsym(RTLD_NEXT, "mmap");
			if (NULL == old_mmap) {
				fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
			}
		}
		if (!init_called ||flag_bypass_mmap || (__flags & MAP_BYPASS))
		{
			return old_mmap(__addr, __len, __prot, __flags & ~(MAP_BYPASS), __fd, __offset);
		}
		void* ret;
		if ( (__flags & (MAP_ANONYMOUS | MAP_PRIVATE) ) && !(__flags & MAP_STACK))
		{
			int myprot = __prot;
			if (isCaptureAll)
				myprot = myprot & ~(PROT_WRITE);
			ret = old_mmap(__addr, __len, myprot, __flags, __fd, __offset);
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
						fprintf(stderr, "mprotect single %016x", (uintptr_t)ret + i * PageSize);
				}
			}
		}
		else
		{
			ret = old_mmap(__addr, __len, __prot, __flags, __fd, __offset);
		}
		//fprintf(stderr, "%p=mmap(%zd)\n", ret, __len);
		return ret;
	}

	void* mmap(void *__addr, size_t __len, int __prot,
		int __flags, int __fd, __off_t __offset) __attribute__((alias("quail_mmap")));


	/*typedef ssize_t(*ptrread)(int __fd, void *__buf, size_t __nbytes);
	static ptrread old_read = NULL;

	ssize_t quail_read(int __fd, void *__buf, size_t __nbytes)
	{
	if (!old_read)
	{
	old_read = (ptrread)dlsym(RTLD_NEXT, "read");
	if (NULL == old_read) {
	fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
	}
	}

	fprintf(stderr, "read %d\n", __fd);
	ssize_t ret = old_read(__fd, __buf, __nbytes);
	return ret;
	}

	void* __read(int __fd, void *__buf, size_t __nbytes) __attribute__((alias("quail_read")));*/



	/*
	typedef int(*ptrbrk)(void *addr);
	ptrbrk old_brk = nullptr;
	std::atomic<void*> brk_addr = { nullptr };

	int quail_brk(void *addr)
	{
	if (!old_brk)
	{
	old_brk = (ptrbrk)dlsym(RTLD_NEXT, "brk");
	if (NULL == old_brk) {
	fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
	}
	}
	int ret = old_brk(addr);
	fprintf(stderr, "%d=brk(%p)\n", ret, addr);
	return ret;
	}
	int brk(void *addr) __attribute__((alias("quail_brk")));

	typedef void*(*ptrsbrk)(intptr_t delta);
	ptrsbrk old_sbrk = nullptr;

	void* quail_sbrk(intptr_t delta)
	{
	if (!old_sbrk)
	{
	old_sbrk = (ptrsbrk)dlsym(RTLD_NEXT, "sbrk");
	if (NULL == old_sbrk) {
	fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
	}
	}
	void* ret = old_sbrk(delta);
	fprintf(stderr, "%p=sbrk(%ld)\n", ret, delta);
	return ret;
	}

	void *sbrk(intptr_t delta) __attribute__((alias("quail_sbrk")));

	//*/
}