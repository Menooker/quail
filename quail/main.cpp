#include <cstdio>
#include <sys/mman.h>
#include <unistd.h>  
#include <string.h>
#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include "LockFreeHashmap.h"
//int mprotect(const void *start, size_t len, int prot);
using namespace std::chrono;
#include <sys/wait.h>

static size_t PageSize = sysconf(_SC_PAGESIZE);
void fib(int* p)
{
	for (int i = 2; i < PageSize * 2 / sizeof(int); i++)
	{
		p[i] = p[i - 1] + p[i - 2];
	}
}

void run(int* foo)
{
	auto start = system_clock::now();
	fib(foo);
	auto end = system_clock::now();
	std::cout << "Time:" << std::chrono::duration_cast<microseconds>(end - start).count()<<" micro sec\n";
	printf("get value %d\n", foo[1000]);
}

void maptest()
{
	quail::LockFreeHashmap<2, uint64_t, int> map;
	map.insert(1, 2);
	map.insert_if_absent(1, 3);
	map.insert_if_absent(2, 3);
	map.insert_if_absent(2, 4);
	map.foreach([](uint64_t key, int value) {
		std::cout << key << "," << value << std::endl;
		return true;
	});
	return ;
}




#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
char mappath[100];
int pagemapfd = 0;
#define    DIRTY_BIT_MASK  (((uint64_t)1)<<55)
int IsPageModified(uintptr_t vir, bool& out)
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
		perror("read  failed");
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
		fprintf(stderr, "File %s", mappath);
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

void softdirtytest()
{
	int* foo = (int*)mmap(nullptr, PageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	std::thread th = std::thread([foo]() {
		ClearDirtyBit();
		bool out;
		IsPageModified((uintptr_t)foo, out);
		printf("dirty %d\n", out);

		ClearDirtyBit();
		std::this_thread::sleep_for(std::chrono::seconds(5));
		IsPageModified((uintptr_t)foo, out);
		printf("dirty %d\n", out);
	});
	foo[0] = 1;
	th.join();
}
//#include <sys/stat.h>
int main2(void)
{
	//lstat("", nullptr);
	//stat("", nullptr);
	snprintf(mappath, sizeof(mappath), "/proc/%d/clear_refs", getpid());
	//fprintf(stderr, "DLL load\n");
	char path[100];
	snprintf(path, sizeof(path), "/proc/%d/pagemap", getpid());
	pagemapfd = open(path, O_RDONLY);
	if (pagemapfd<0)
	{
		perror("open /proc/self/pagemap failed");
	}
	//softdirtytest();
	//InitSignal();
	int *foo = nullptr;
	//foo=(int*)mmap(nullptr, PageSize*2, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	foo= (int*)malloc(PageSize * 2);
	//foo = new int[PageSize * 200 / sizeof(int)];
	printf("The pointer is %p\n", foo);
	foo[0] = 1;
	foo[1] = 1;
	//fib(foo);
	printf("get value %d\n", foo[1000]);
	run(foo);

	//foo = (int*)malloc(PageSize * 2);//mmap(nullptr, PageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	foo[0] = 1;
	foo[1] = 1;
	run(foo);
	printf("get value %d\n", foo[1000]);
	std::cout << "Wait for 5 sec\n";
	std::this_thread::sleep_for(std::chrono::seconds(5));
	run(foo);
	/*auto func = [foo](int id)
	{
		foo[id*PageSize / sizeof(int)+1] = 23;
	};
	std::thread t1(func, 0);
	std::thread t2(func, 1);
	t1.join();
	t2.join();*/
	//getchar();
	/*{
		int pbPid = 0;
		int& returnValue=foo[0];
		if ((pbPid = fork()) == 0)
		{
			printf("Child\n");
			char* arg[] = { " --help",0 }; //argument to program b
			execv("g++", arg);
		}
		else
		{
			if (waitpid(pbPid, &returnValue, 0)<0)
				perror("Wait Error");
		}
		returnValue = WEXITSTATUS(returnValue);
		return 0;
	}*/
	return 0;
}


extern void PrintInstruction(uint8_t * instr);
extern int DoInterpreteSize(uint8_t * instr, int& outsize);
int main()
{
	unsigned char a[] = { 0x4c,0x89,0x47,0x08 ,0xcc,0xcc};
	PrintInstruction(a);
	int sz;
	DoInterpreteSize(a, sz);
	printf("%d\n", sz);
}