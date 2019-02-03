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
#include <sys/stat.h>
#include <limits.h>
#include "PFishHook.h"
#include "HookFunction.h"
#include <ucontext.h>
#include <pthread.h>
#include "CountMinSketch.h"

static std::thread LockerThread;
bool init_called = false;
bool need_wear_leveling = false;
static bool is_adaptive_sampling = false;

extern BypassAlloactor alloactor;
extern quail::LockFreeHashmap<4096, uintptr_t, PageInfo*, BypassAlloactor> page_map;
extern thread_local bool flag_bypass_mmap;

extern bool isCaptureAll;
static FILE* outfile=nullptr;
static int sample_interval = 100;
static uint64_t swap_threshold = 1000;
static uint64_t swap_threshold_increment = 1000;

#ifdef __GNUC__
#define  likely(x)        __builtin_expect(!!(x), 1) 
#define  unlikely(x)      __builtin_expect(!!(x), 0) 
#else
#define  likely(x)        (x)
#define  unlikely(x)      (x)
#endif

#define EFLAG_TF_MASK ((uint64_t)1<<8)

void* SingleStepPage = nullptr;
int SingleStepProt = 0;
int SingleStepSize = 0;
void* LastFault = 0;

std::mutex GlobalCaptureLock;
thread_local bool local_locked = false;


typedef void(*ptrsignalhandler)(int signal, siginfo_t *si, void *arg);
ptrsignalhandler old_segfault_sigaction;
ptrsignalhandler old_trap_sigaction;
extern void InitInterpreter();
typedef void* PVOID;
extern int DoInterprete(uint8_t * instr, ucontext* context, PVOID& outfrom, PVOID& outto, int& outsize);
extern int DoInterpreteSize(uint8_t * instr, int& outsize,uint64_t rcx);
extern void PrintInstruction(uint8_t * instr);

static quail::CMSCounter<std::atomic<uint64_t>, 511> cmscounter[2];
static int current_counter_idx = 0;

int sigaction_bypass(int sig, const struct sigaction *__restrict act,
	struct sigaction *__restrict oact);
struct sigaction SEGVData= { 0 };
struct sigaction TRAPData = { 0 };

static void MRestoreRange(void* ptr, size_t n)
{
	char* start = (char*)AlignToPage(ptr);

	for (char* i = start; i <= (char*)ptr + n - 1; i += PageSize)
	{
		auto itm = page_map.find((uintptr_t)i);
		if (!itm)
			continue;
		itm->unprotected = true;
	}
}

static void MProtectRange(void* ptr, size_t n, bool writable)
{
	char* start = (char*)AlignToPage(ptr);
	int prot = -1;
	int mask = writable ? 0xffffffff : ~PROT_WRITE;
	int cnt = 0;
	for (char* i = start; i <= (char*)ptr + n - 1; i += PageSize)
	{
		auto itm = page_map.find((uintptr_t)i);
		if (!itm)
			goto TOUCH_ALL;
		if (prot == -1)
		{
			prot = itm->prot;
		}
		else if(prot != itm->prot)
		{
			goto TOUCH_ALL;
		}
		itm->unprotected = !writable;
		cnt++;
		//itm->count++;
	}
	if (prot != -1)
	{
		//if (!writable && (uintptr_t)start >> 32 == 0)
		//	fprintf(stderr, "mprotect chunk %p, size %d\n", start,cnt);
		int status;
		if ((status = mprotect(start, cnt * PageSize, prot & mask)) != 0)
		{
			fprintf(stderr, "Signal: Set protect error: %d\n", status);
		}
	}
	return;
TOUCH_ALL:
	//fprintf(stderr, "TOUCH_ALL\n");
	for (char* i = start; i <= (char*)ptr + n - 1; i += PageSize)
	{
		auto itm = page_map.find((uintptr_t)i);
		if (itm)
		{
			//itm->count++; //fix-me : use the correct count
			//if (!writable && (uintptr_t)i >> 32 == 0)
			//	fprintf(stderr, "mprotect single %016x", i);
			mprotect(i, PageSize, itm->prot & mask);
		}
	}
}


PageInfo* get_page_info(uintptr_t p)
{
	return page_map.find(p);
}

extern void QuailSwapPage(void* ptr, PageInfo* pinfo);

void segfault_sigaction(int sig, siginfo_t *si, void *arg)
{
	auto itm = page_map.find((uintptr_t)AlignToPage(si->si_addr));
	if (unlikely(itm == nullptr || IsPageNotWritable(itm)))
	{
		fprintf(stderr, "call old seg %p, page %p , itm=%p\n", 
			old_segfault_sigaction, si->si_addr,itm);
		//sleep(-1);
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

	if (isCaptureAll)
	{
		if (!local_locked)
		{
			GlobalCaptureLock.lock(); 
			local_locked = true;
		}
		//fprintf(stderr, "Caught segfault at address %p\n", si->si_addr);
		ucontext* context = (ucontext*)arg;
		SingleStepPage = AlignToPage(si->si_addr);
		SingleStepProt = itm->prot;
		//if (mprotect(AlignToPage(si->si_addr), PageSize*2, itm->prot) != 0)
		//{
		uintptr_t delta = (uintptr_t)AlignToPage(si->si_addr) + PageSize - (uintptr_t)si->si_addr;
		SingleStepSize = PageSize;
		if (delta < 512 / 8) //check if the memory access span accross two pages
		{
				LastFault = AlignToPage(si->si_addr);
		}
		else
		{
			if (LastFault== (char*)AlignToPage(si->si_addr) - PageSize && AlignToPage(si->si_addr) == si->si_addr)
			{
				auto itm2 = page_map.find((uintptr_t)LastFault);
				if (itm2)
				{
					SingleStepPage = LastFault;
					SingleStepSize = 2 * PageSize;
					mprotect(LastFault, PageSize, itm2->prot);
				}
			}
			LastFault = 0;
		}
		int status;
		if ((status=mprotect(AlignToPage(si->si_addr), PageSize, itm->prot)) != 0)
		{
			fprintf(stderr,"Signal: Set protect error: %d\n",status);
		}
		context->uc_mcontext.gregs[REG_EFL]|= EFLAG_TF_MASK;
	}
	else
	{
		if (mprotect(AlignToPage(si->si_addr), PageSize, itm->prot) != 0)
		{
			perror("Signal: Set protect error: ");
		}
	}

	cmscounter[current_counter_idx].Put((uintptr_t)si->si_addr);

	uint64_t newcnt=itm->GetCount()++;
	itm->unprotected = true;
	if (need_wear_leveling && newcnt > swap_threshold)
	{
		QuailSwapPage(AlignToPage(si->si_addr), itm);
		swap_threshold = itm->GetCount() + swap_threshold_increment;
	}
}
void trap_sigaction(int sig, siginfo_t *si, void *arg)
{
	ucontext* context = (ucontext*)arg;
	//fprintf(stderr, "trap fault %p\n", si->si_addr);
	if (si->si_addr == (char*)segfault_sigaction + 2)
	{
		fprintf(stderr, "Double fault\n");
		//sleep(-1);
	}
	//fprintf(stderr, "TRAP!\n");
	if (SingleStepPage)
	{
		//if (mprotect(SingleStepPage, PageSize * 2, SingleStepProt & ~(PROT_WRITE)) != 0)
		//{
		int status;
		if ((status=mprotect(SingleStepPage, PageSize, SingleStepProt & ~(PROT_WRITE))) != 0)
		{
			fprintf(stderr, "Signal: Set protect error: %d\n", status);
		}
		if (SingleStepSize == 2 * PageSize)
		{
			mprotect(SingleStepPage, PageSize, SingleStepProt & ~(PROT_WRITE));
		}
		else if (SingleStepSize > 2 * PageSize)
		{
			fprintf(stderr, "Bad page size %d\n", SingleStepSize);
		}
		//}
		
		//fprintf(stderr, "TRAP %p! page %p\n", si->si_addr, SingleStepPage);

		SingleStepPage = nullptr;
		context->uc_mcontext.gregs[REG_EFL] &= ~EFLAG_TF_MASK;
		if (local_locked)
		{
			local_locked = false;
			GlobalCaptureLock.unlock();
		}

	}
	else
	{
		if ((uintptr_t)old_trap_sigaction == 0)
		{
			struct sigaction sa;
			memset(&sa, 0, sizeof(struct sigaction));
			sigemptyset(&sa.sa_mask);
			sa.sa_handler = SIG_DFL;
			sa.sa_flags = SA_SIGINFO;

			sigaction_bypass(SIGTRAP, &sa, nullptr);
			raise(sig);
			return;
		}
		else if ((uintptr_t)old_trap_sigaction == 1)
		{
			return;
		}
		old_trap_sigaction(sig, si, arg);
		return;
	}
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

def_name(read, ssize_t, int , void *, size_t);
typedef ssize_t(*ptrfread)(FILE* fd, void *buf, size_t nbytes);
ptrfread old_IO_file_read;
int cnt = 0;
extern "C" ssize_t myread(int fd, void *buf, size_t nbytes)
{
	//fprintf(stderr, "[read] bytes %zu buf %p %d\n", nbytes,buf,cnt++);
	//if (isCaptureAll)
	MProtectRange(buf, nbytes,true);
	//else
	//	TouchRange(buf, nbytes);
	ssize_t ret = CallOld<Name_read>(fd, buf, nbytes);
	if (isCaptureAll)
		MProtectRange(buf, nbytes, false);
	else
		MRestoreRange(buf, nbytes);
	//fprintf(stderr, "[read] ret%d\n", ret);
	return ret;
}

extern "C" ssize_t myfileread(FILE* fp, void *buf, size_t nbytes)
{
	//fprintf(stderr, "[fileread] bytes %zu buf %p %d\n", nbytes,buf,cnt++);
	//if (isCaptureAll)
	MProtectRange(buf, nbytes, true);
	//else
	//	TouchRange(buf, nbytes);
	ssize_t ret = old_IO_file_read(fp, buf, nbytes);
	if (isCaptureAll)
		MProtectRange(buf, nbytes, false);
	else
		MRestoreRange(buf, nbytes);
	return ret;
}

def_name(pthread_once, int, pthread_once_t *, void(*) (void));
int mypthread_once(pthread_once_t *__once_control,
	void(*__init_routine) (void))
{
	if(!init_called)
		return CallOld<Name_pthread_once>(__once_control, __init_routine);

	auto itm = page_map.find((uintptr_t)AlignToPage(__once_control));
	if (itm)
	{
		fprintf(stderr, "pthread in heap %p\n", __once_control);
		itm->unprotected = false;
		mprotect(AlignToPage(__once_control), PageSize, itm->prot);
	}
	//MProtectRange(__once_control, sizeof(pthread_once_t), true);

	int ret = CallOld<Name_pthread_once>(__once_control, __init_routine);
	return ret;
}



def_name(__xstat, int, int, const char *, struct stat *);
auto my_stat = [](int ver, const char *__restrict file, struct stat *__restrict buf)->int {
	fprintf(stderr, "stat %s\n", file);
	//if (isCaptureAll)
		MProtectRange(buf, sizeof(struct stat), true);
	//else
	//	TouchRange(buf, sizeof(struct stat));
	auto ret = CallOld<Name___xstat>( ver, file, buf);
	if (isCaptureAll)
		MProtectRange(buf, sizeof(struct stat), false);
	else
		MRestoreRange(buf, sizeof(struct stat));
	return ret;
};
extern "C" int __xstat(int ver, const char *__restrict file, struct stat *__restrict buf) {
	return CallHooked<Name___xstat>(my_stat, ver, file, buf);
}

def_name(__lxstat, int, int, const char *, struct stat *);
extern "C" int mylxstat(int ver, const char *__restrict file, struct stat *__restrict buf) {
	//if (isCaptureAll)
		MProtectRange(buf, sizeof(struct stat), true);
	//else
	//	TouchRange(buf, sizeof(struct stat));
	auto ret = CallOld<Name___lxstat>(ver, file, buf);
	if (isCaptureAll)
		MProtectRange(buf, sizeof(struct stat), false);
	else
		MRestoreRange(buf, sizeof(struct stat));
	return ret;
}

def_name(__fxstat,int, int , int , struct stat *);
auto my_fstat = [](int ver, int fd, struct stat *buf)->int {
	//if (isCaptureAll)
		MProtectRange(buf, sizeof(struct stat), true);
	//else
	//	TouchRange(buf, sizeof(struct stat));
	auto ret = CallOld<Name___fxstat>(ver, fd, buf);
	if (isCaptureAll)
		MProtectRange(buf, sizeof(struct stat), false);
	else
		MRestoreRange(buf, sizeof(struct stat));
	return ret;
};
extern "C" int __fxstat(int ver, int fd, struct stat *buf)
{
	return CallHooked<Name___fxstat>(my_fstat, ver, fd, buf);
}


/*extern "C" unsigned int alarm(unsigned int time)
{
	return time;
}*/
///////////////////



static void LockerThreadProc()
{
	for (;;)
	{
		//fprintf(stderr, "Locker Thread\n");
		float simi = cmscounter[0].Similarity(cmscounter[1]);
		fprintf(stderr, "Similarity %f\n", simi);
		if (is_adaptive_sampling)
		{
			if (simi > 0.9)
				sample_interval -= 50;
			if (simi < 0.9)
				sample_interval += 50;
			sample_interval = std::max(sample_interval, 50);
			sample_interval = std::min(sample_interval, 400);
		}
		current_counter_idx = (current_counter_idx + 1) % 2;
		cmscounter[current_counter_idx].Reset();
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
		fprintf(stderr, "Sleep %d\n", sample_interval);
		std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval));
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
		fprintf(stderr, "sigaction(SIGSEGV) called\n");
		if(act)
			old_segfault_sigaction = (ptrsignalhandler) act->sa_sigaction;
		if (oact)
			*oact = SEGVData;
		return 0;
	}
	if (sig = SIGTRAP)
	{
		fprintf(stderr, "sigaction(SIGTRAP) called\n");
		if (act)
			old_trap_sigaction = (ptrsignalhandler)act->sa_sigaction;
		if (oact)
			*oact = TRAPData;
		return 0;
	}
	return old_sigaction(sig, act, oact);
}

ptrsignalhandler SetSignal(int sig, ptrsignalhandler handler,struct sigaction* oldsa)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	memset(oldsa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction_bypass(sig, &sa, oldsa))
		perror("sigaction");
	return oldsa->sa_sigaction;
}

void InitSignal()
{

	old_segfault_sigaction = SetSignal(SIGSEGV, segfault_sigaction,&SEGVData);
	if (!isCaptureAll)
	{
		flag_bypass_mmap = true;
		LockerThread = std::move(std::thread(LockerThreadProc));
		LockerThread.detach();
		flag_bypass_mmap = false;
	}
	else
	{
		old_trap_sigaction = SetSignal(SIGTRAP, trap_sigaction,&TRAPData);
	}
}


__attribute__((constructor)) static void OnInit(void);
__attribute__((destructor)) static void OnExit(void);

extern "C" void quail_hook_mem_alloc_funcs();

void OnInit()
{
	if (init_called)
		return;
	if (PageSize == 0)
		PageSize = sysconf(_SC_PAGESIZE);
	char* pEnv = getenv("QUAIL_CAPTURE_ALL");
	if (pEnv && pEnv[0] == '1' && pEnv[1] == 0)
	{
		isCaptureAll = true;
	}
	pEnv = getenv("QUAIL_OUTPUT");
	if (pEnv && pEnv[0] == 0 || !pEnv)
	{
		outfile=stderr;
	}
	else
	{
		outfile = fopen(pEnv, "a");
	}

	pEnv = getenv("QUAIL_INTERVAL");
	if (pEnv && pEnv[0] == 0 || !pEnv)
	{
		sample_interval = 100;
	}
	else
	{
		sample_interval = atoi(pEnv);
	}

	pEnv = getenv("QUAIL_SWAP_THRESHOLD");
	if (pEnv && pEnv[0] == 0 || !pEnv)
	{
		swap_threshold = 1000;
	}
	else
	{
		swap_threshold = atoi(pEnv);
	}

	pEnv = getenv("QUAIL_SWAP_THRESHOLD_INC");
	if (pEnv && pEnv[0] == 0 || !pEnv)
	{
		swap_threshold_increment = 1000;
	}
	else
	{
		swap_threshold_increment = atoi(pEnv);
	}

	pEnv = getenv("QUAIL_ADAPTIVE_SAMPLING");
	if (pEnv && pEnv[0] == '1' && pEnv[1] == 0)
		is_adaptive_sampling = true;
	//fprintf(stderr, "DLL load\n");
	HookStatus ret;
	DoHook<Name_read>(myread);
	DoHook<Name___lxstat>(mylxstat);
	DoHook<Name_pthread_once>(mypthread_once);
	void* p_IO_file_read = dlsym(RTLD_NEXT, "_IO_file_read");
	if (p_IO_file_read)
	{
		if ((ret = HookIt(p_IO_file_read, (void**)&old_IO_file_read, (void*)myfileread)) != 0)
		{
			fprintf(stderr, "Hook error %d\n", ret);
			exit(1);
		}
	}
	//sleep(20);
	InitInterpreter();
	InitSignal();
	init_called = true;
	pEnv = getenv("QUAIL_PROFILE_MODE");
	if (pEnv && pEnv[0] == '1' && pEnv[1] == 0)
		quail_hook_mem_alloc_funcs();
	else
		need_wear_leveling = true;
		
}

void OnExit()
{
	page_map.foreach([](const uintptr_t& page, const PPageInfo& info) {
		//std::cout << "Page " << page << " Count = " << (unsigned)info->count << std::endl;
		//if(info->count>0)
		fprintf(outfile, "Page %p Count = %d\n", (void*)page, (unsigned)info->GetCount());
		return true;
	});
	//page_map.stat();
}
