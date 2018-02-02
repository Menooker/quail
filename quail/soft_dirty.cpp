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
#include "PageInfo.h"
#include "util.h"
#include "BypassAlloactor.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mutex>


__attribute__((constructor)) static void OnInit(void);
__attribute__((destructor)) static void OnExit(void);
bool init_called=false;
static bool thread_do_exit = false;
int pagemapfd = 0;
static std::thread WatcherThread;
//std::timed_mutex time_lock;

#define    page_map_file     "/proc/self/pagemap"
#define    DIRTY_BIT_MASK  (((uint64_t)1)<<55)

extern quail::LockFreeHashmap<4096, uintptr_t, PageInfo*, BypassAlloactor> page_map;
char mappath[100];
extern thread_local bool flag_bypass_mmap ;


int IsPageModified(uintptr_t vir,bool& out)
{
	int page_size = PageSize;
	unsigned long vir_page_idx = vir / page_size;
	unsigned long pfn_item_offset = vir_page_idx * sizeof(uint64_t);
	uint64_t pfn_item;

	if ((off_t)-1 == lseek(pagemapfd, pfn_item_offset, SEEK_SET))
	{
		perror("lseek /proc/self/pagemap failed");
		return -1;
	}
	if (sizeof(uint64_t) != read(pagemapfd, &pfn_item, sizeof(uint64_t)))
	{
		printf("read %s failed", page_map_file);
		return -1;
	}
	out = pfn_item & DIRTY_BIT_MASK;
	return 0;
}
int ClearDirtyBit()
{
	int fd = open(mappath, O_WRONLY);
	if (fd<0)
	{
		perror("open failed");
		return -1;
	}

	if (1 != write(fd, "4", 1))
	{
		perror("write failed");
		return -1;
	}
	close(fd);
	return 0;
}



void WatcherThreadProc()
{
	flag_bypass_mmap = true;
	while (!thread_do_exit)
	{
		ClearDirtyBit();
		//sleep for some time or let the main thread wake me up
		//time_lock.try_lock_for(std::chrono::milliseconds(150));
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		if (thread_do_exit)
			break;
		page_map.foreach([](const uintptr_t& page, const PPageInfo& info) {
			bool modified;
			if (thread_do_exit)
				return false;
			if (IsPageModified(page, modified) == 0 && modified)
			{
				info->count++;
			}
			return true;
		});
	}
}


void OnInit()
{
	if (init_called)
		return;
	flag_bypass_mmap = true;
	snprintf(mappath, sizeof(mappath), "/proc/%d/clear_refs", getpid());
	//fprintf(stderr, "DLL load\n");
	char path[100];
	snprintf(path, sizeof(path), "/proc/%d/pagemap", getpid());
	pagemapfd = open(path, O_RDONLY);
	if (pagemapfd<0)
	{
		perror("open /proc/self/pagemap failed");
	}
	//time_lock.lock();
	WatcherThread = std::move(std::thread(WatcherThreadProc));
	WatcherThread.detach();

	init_called = true;
	flag_bypass_mmap = false;
}

void OnExit()
{
	//time_lock.unlock();
	thread_do_exit = true;
	close(pagemapfd);
	page_map.foreach([](const uintptr_t& page, const PPageInfo& info) {
		//std::cout << "Page " << page << " Count = " << (unsigned)info->count << std::endl;
		if (info->count>2)
			fprintf(stderr, "Page %p Count = %d\n", (void*)page, (unsigned)info->count);
		return true;
	});
}