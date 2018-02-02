//#define _GNU_SOURCE

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
#include "HookFunction.h"
#include <sys/stat.h>
#include <limits.h>
#include "PFishHook.h"

static std::thread LockerThread;
bool init_called = false;


extern BypassAlloactor alloactor;
extern quail::LockFreeHashmap<4096, uintptr_t, PageInfo*, BypassAlloactor> page_map;
extern thread_local bool flag_bypass_mmap;



#ifdef __GNUC__
#define  likely(x)        __builtin_expect(!!(x), 1) 
#define  unlikely(x)      __builtin_expect(!!(x), 0) 
#else
#define  likely(x)        (x)
#define  unlikely(x)      (x)
#endif

extern thread_local bool MallocTouch;
static void(*old_segfault_sigaction)(int signal, siginfo_t *si, void *arg);

int sigaction_bypass(int sig, const struct sigaction *__restrict act,
	struct sigaction *__restrict oact);
void segfault_sigaction(int sig, siginfo_t *si, void *arg)
{
	//fprintf(stderr,"Caught segfault at address %p\n", si->si_addr);
	auto itm = page_map.find((uintptr_t)AlignToPage(si->si_addr));
	if (unlikely(itm == nullptr || IsPageNotWritable(itm)))
	{
		fprintf(stderr, "call old seg %p, page %p , itm=%p\n", 
			old_segfault_sigaction, si->si_addr,itm);
		if ((uintptr_t)old_segfault_sigaction == 0)
		{
			//printf("call default handler\n");
			struct sigaction sa;
			memset(&sa, 0, sizeof(struct sigaction));
			sigemptyset(&sa.sa_mask);
			sa.sa_handler = SIG_DFL;
			sa.sa_flags = SA_SIGINFO;

			sigaction_bypass(SIGSEGV, &sa, nullptr);
			raise(sig);
			return;
		}
		else if ((uintptr_t)old_segfault_sigaction == 1)
		{
			return;
		}
		old_segfault_sigaction(sig, si, arg);
		return;
	}

	if (mprotect(AlignToPage(si->si_addr), PageSize, itm->prot) != 0)
	{
		perror("Signal: Set protect error: ");
	}
	itm->count++;
	itm->unprotected = true;
	//printf("Found item\n");
}

//////////////////
/*
Special patch for gcc to avoid "Bad address" error
*/
typedef __pid_t(*ptrwaitpid)(__pid_t __pid, int *__stat_loc, int __options);
static ptrwaitpid old_waitpid = nullptr;


extern "C" __pid_t waitpid(__pid_t __pid, int *__stat_loc, int __options)
{
	if (!old_waitpid)
	{
		old_waitpid = (ptrwaitpid)dlsym(RTLD_NEXT, "waitpid");
		if (NULL == old_waitpid) {
			fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
		}
	}
	int stat = 0;
	__pid_t ret = old_waitpid(__pid, &stat, __options);
	*__stat_loc = stat;
	return ret;
}




/*
def_name(fread);

auto my_fread=[](void *__restrict ptr, size_t size, size_t n, FILE *__restrict stream)->size_t {
		fprintf(stderr, "fread2 %p\n", stream);
		TouchRange(ptr, size*n);
		return CallOld(Name_fread(), size_t(), ptr, size, n, stream);
};
extern "C" size_t fread(void *__restrict ptr, size_t size, size_t n, FILE *__restrict stream)
{
	return CallHooked(Name_fread(), my_fread ,size_t(),ptr, size, n, stream);
}*/

typedef ssize_t(*ptrread)(int fd, void *buf, size_t nbytes);
ptrread oldread;
extern "C" ssize_t myread(int fd, void *buf, size_t nbytes)
{
	//fprintf(stderr, "[read] bytes %d buf %p\n", nbytes,buf);
	TouchRange(buf, nbytes);
	ssize_t ret = oldread(fd, buf, nbytes);
	//fprintf(stderr, "[read] ret%d\n", ret);
	return ret;
}
/*
def_name(readlink);
auto my_readlink = [](const char *__restrict path, char *__restrict buf, size_t len) -> ssize_t
{
	fprintf(stderr, "readlink %s\n", path);
	TouchRange(buf, len);
	return CallOld(Name_readlink(), ssize_t(), path, buf, len);
};
extern "C" ssize_t readlink(const char *__restrict path, char *__restrict buf, size_t len)
{
	return CallHooked(Name_readlink(), my_readlink, ssize_t(), path, buf, len);
}

def_name(__xstat)
auto my_stat = [](int ver, const char *__restrict file, struct stat *__restrict buf)->int {
	//fprintf(stderr, "stat %s\n", file);
	TouchRange(buf, sizeof(struct stat));
	return CallOld(Name___xstat(), int(0),ver, file, buf);
};
extern "C" int __xstat(int ver, const char *__restrict file, struct stat *__restrict buf) {
	return CallHooked(Name___xstat(), my_stat, int(), ver, file, buf);
}


def_name(__lxstat)
auto my_lstat = [](int ver, const char *__restrict file, struct stat *__restrict buf)->int {
	fprintf(stderr, "lstat2 %s\n", file);
	TouchRange(buf, sizeof(struct stat));
	return CallOld(Name___lxstat(), int(0), ver, file, buf);
};
extern "C" int __lxstat(int ver,const char *__restrict file, struct stat *__restrict buf) {
	return CallHooked(Name___lxstat(), my_lstat, int(),ver, file, buf);
}

def_name(__realpath_chk);
auto my_realpath = [](const char *__restrict file, char *__restrict buf, size_t resolvedlen)->char* {
	
	if (buf)
	{
		TouchRange(buf, resolvedlen);
	}
	else
	{
		fprintf(stderr, "realpath %s\n", file);
	}
	MallocTouch = true;
	char* ret= CallOld(Name___realpath_chk(), (char*)(0),  file, buf, resolvedlen);
	MallocTouch = false;
	return ret;
};
extern "C" char* __realpath_chk(const char *__restrict file, char *__restrict buf, size_t resolvedlen) {
	return CallHooked(Name___realpath_chk(), my_realpath, (char*)(0),  file, buf,resolvedlen);
}



def_name(__fxstat);
auto my_fstat = [](int ver,int fd, struct stat *buf)->int {
	//fprintf(stderr, "fstat %d\n", fd);
	TouchRange(buf, sizeof(struct stat));
	return CallOld(Name___fxstat(), int(),ver, fd, buf);
};
extern "C" int __fxstat(int ver,int fd, struct stat *buf)
{
	return CallHooked(Name___fxstat(), my_fstat, int(),ver, fd, buf);
}
*/
/*
typedef size_t (*ptrfread)(void *__restrict ptr, size_t size, size_t n, FILE *__restrict stream);
static ptrfread old_fread = nullptr;
static ptrfread old_fread_unlocked = nullptr;
extern "C" size_t fread(void *__restrict ptr, size_t size,size_t n, FILE *__restrict stream)
{
	if (!old_fread)
	{
		old_fread = (ptrfread)dlsym(RTLD_NEXT, "fread");
		if (NULL == old_fread) {
			fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
		}
	}
	if (!init_called)
	{
		return old_fread(ptr, size, n, stream);
	}
	//fprintf(stderr, "fread %p\n", stream);
	TouchRange(ptr, size*n);
	return old_fread(ptr, size, n, stream);
}*/
/*
extern "C" size_t fread_unlocked(void *__restrict ptr, size_t size, size_t n, FILE *__restrict stream)
{
	if (!old_fread_unlocked)
	{
		old_fread_unlocked = (ptrfread)dlsym(RTLD_NEXT, "fread_unlocked");
		if (NULL == old_fread_unlocked) {
			fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
		}
	}
	if (!init_called)
	{
		return old_fread_unlocked(ptr, size, n, stream);
	}
	fprintf(stderr, "old_fread_unlocked %p\n", stream);
	TouchRange(ptr, size*n);
	return old_fread_unlocked(ptr, size, n, stream);
}
*/
typedef char* (*ptrfgets)(char *__restrict __s, int __n, FILE *__restrict __stream);
ptrfgets old_fgets = nullptr;
extern "C" char *fgets(char *__restrict s, int n, FILE *__restrict stream)
{
	if (!old_fgets)
	{
		old_fgets = (ptrfgets)dlsym(RTLD_NEXT, "fgets");
		if (NULL == old_fgets) {
			fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
		}
	}
	if (!init_called)
	{
		return old_fgets(s,  n, stream);
	}
	fprintf(stderr, "gets %p\n", stream);
	TouchRange(s, n);
	return old_fgets(s, n, stream);
}

///////////////////



static void LockerThreadProc()
{
	for (;;)
	{
		//fprintf(stderr, "Locker Thread\n");
		page_map.foreach([](const uintptr_t& page, const PPageInfo& info) {
			if (info->unprotected)
			{
				if (mprotect((void*)page, PageSize, info->prot & ~(PROT_WRITE)) != 0)
				{
					//fprintf(stderr, "LockerThread: %p, len=%zd - ", (void*)page, PageSize);
					//perror("Set protect error: ");
				}
				info->unprotected = false;
			}
			return true;
		});
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	}
}

static void* LockerThreadProcWraper(void*)
{
	fprintf(stderr, "ThreadRun\n");
	LockerThreadProc();
	return nullptr;
}




typedef __sighandler_t(*ptrsignal)(int sig, __sighandler_t handler);
static ptrsignal old_signal = nullptr;
typedef int(*ptrsigaction)(int sig, const struct sigaction *__restrict act,
	struct sigaction *__restrict oact);
static ptrsigaction old_sigaction = nullptr;

static thread_local bool SignalBypass = false;

__sighandler_t signal_bypass(int sig, __sighandler_t handler)
{
	SignalBypass = true;
	auto ret = signal(sig,handler);
	SignalBypass = false;
	return ret;
}


extern "C" __sighandler_t signal(int sig, __sighandler_t handler)
{
	if (!old_signal)
	{
		old_signal = (ptrsignal)dlsym(RTLD_NEXT, "signal");
		if (NULL == old_signal) {
			fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
		}
	}
	if (SignalBypass)
	{
		return old_signal(sig,handler);
	}
	
	
	if (sig = SIGSEGV)
	{
		//fprintf(stderr, "signal() called\n");
		__sighandler_t ret = (__sighandler_t)old_segfault_sigaction;
		*(__sighandler_t*)(&old_segfault_sigaction) = handler;
		return ret;
	}
	return old_signal(sig,handler);
}

int sigaction_bypass(int sig, const struct sigaction *__restrict act,
	struct sigaction *__restrict oact)
{
	SignalBypass = true;
	auto ret = sigaction(sig, act,oact);
	SignalBypass = false;
	return ret;
}

extern "C" int sigaction(int sig, const struct sigaction *__restrict act,
	struct sigaction *__restrict oact)
{
	if (!old_sigaction)
	{
		old_sigaction = (ptrsigaction)dlsym(RTLD_NEXT, "sigaction");
		if (NULL == old_sigaction) {
			fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
		}
	}
	if (SignalBypass || !init_called)
	{
		return old_sigaction(sig, act, oact);
	}


	if (sig = SIGSEGV)
	{
		fprintf(stderr, "sigaction() called\n");
		old_segfault_sigaction = act->sa_sigaction;
		return 0;
	}
	return old_sigaction(sig, act, oact);
}

void InitSignal()
{
	struct sigaction sa;
	struct sigaction oldsa;
	memset(&sa, 0, sizeof(struct sigaction));
	memset(&oldsa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = segfault_sigaction;
	sa.sa_flags = SA_SIGINFO;
	
	sigaction_bypass(SIGSEGV, &sa, &oldsa);
	old_segfault_sigaction = oldsa.sa_sigaction;

	flag_bypass_mmap = true;
	LockerThread = std::move(std::thread(LockerThreadProc));
	LockerThread.detach();
	flag_bypass_mmap = false;
	
}


__attribute__((constructor)) static void OnInit(void);
__attribute__((destructor)) static void OnExit(void);

void OnInit()
{
	if (init_called)
		return;
	//fprintf(stderr, "DLL load\n");
	void* pread = dlsym(RTLD_NEXT, "read");
	if (!pread)
	{
		fprintf(stderr, "read not found\n");
		exit(1);
	}
	if (HookIt(pread, (void**)&oldread, (void*)myread) != 0)
	{
		fprintf(stderr, "Hook error\n");
		exit(1);
	}
	
	InitSignal();
	init_called = true;
}

void OnExit()
{
	page_map.foreach([](const uintptr_t& page, const PPageInfo& info) {
		//std::cout << "Page " << page << " Count = " << (unsigned)info->count << std::endl;
		if(info->count>3)
			fprintf(stderr, "Page %p Count = %d\n", (void*)page, (unsigned)info->count);
		return true;
	});
}






/*
void* mymmap(void *__addr, size_t __len, int __prot,
	int __flags, int __fd, __off_t __offset)
{
	if (__flags & MAP_ANONYMOUS)
	{
		void* ret = mmap(__addr, __len, __prot & ~(PROT_WRITE), __flags, __fd, __offset);
		for (unsigned i = 0; i < divide_and_ceil(__len, PageSize); i++)
		{
			page_map.insert(((uintptr_t)ret + i * PageSize), new (malloc_bypass(sizeof(PageInfo))) PageInfo(__prot)); // fix-me : may cause recursive calls to mmap
		}
		return ret;
	}
	return mmap(__addr, __len, __prot, __flags, __fd, __offset);
}*/