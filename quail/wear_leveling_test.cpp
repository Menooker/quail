#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <vector>
#include <sys/mman.h>
#include "LockFreeHashmap.h"
#include <random>

//#define FAKE_WEAR_LEVELING 1

#define BUCKET_SIZE (1024*3-1)

extern "C" void QuailFree(void* ptr);
extern "C" void* QuailAlloc(size_t sz);
extern "C" size_t QuailGetWriteCount(void* ptr);
extern "C" std::atomic<uint64_t>* QuailGetCounters();

constexpr int NVM_SIZE_IN_BYTES = (32 * 1024 * 1024);
constexpr int MAX_ALLOC_SIZE = 30 * 1024 * 1024;
constexpr int ALLOCATOR_BYTES_PER_BIT = 4096;

int counts[NVM_SIZE_IN_BYTES / ALLOCATOR_BYTES_PER_BIT] = { 0 };

struct MyAlloactor
{
	static char* addr;
	static size_t cur_len;
	static const size_t total_len = MAX_ALLOC_SIZE-8;
	static void* alloc(size_t size)
	{
		assert(cur_len + size < total_len);
		size_t ret = cur_len;
		cur_len += size;
		return addr + ret;
	}

	static void release(void* ptr, size_t size)
	{
		fprintf(stderr, "Free called but not implemented.\n");
	}
};
char* MyAlloactor::addr = nullptr;
size_t MyAlloactor::cur_len = 0;

#ifndef FAKE_WEAR_LEVELING
#define STO(var,val) var=val
#else
template <typename T>
void DoStore(T& var, T val)
{
	auto offset = (char*)&var - MyAlloactor::addr;
	offset /= ALLOCATOR_BYTES_PER_BIT;
	counts[offset]++;
	var = val;
}
#define STO(var,val) DoStore(var,val)
#endif


template <typename K, typename V,typename Allocator>
class HashMap
{
	struct Node
	{
		K key;
		V value;
		Node* next;
	};

	Node* buckets[BUCKET_SIZE];

public:
	HashMap()
	{
		for (int i = 0; i < BUCKET_SIZE; i++)
		{
			STO(buckets[i] , (Node*)nullptr);
		}
	}

	void Set(K key, V value)
	{
		Node* old_node = GetNode(key);
		if (old_node)
		{
			STO(old_node->value , value);
			return;
		}
		Node*& buck = buckets[quail::Hash<K>::DoHash(key) % BUCKET_SIZE];
		Node* node = (Node*)Allocator::alloc(sizeof(Node));
		STO(node->key, key);
		STO(node->value, value);
		STO(node->next, buck);
		STO(buck, node);
	}

	V Get(K key)
	{
		auto n = GetNode(key);
		if (n)
			return n->value;
		return 0;
	}

private:
	Node* GetNode(K key)
	{
		Node* buck = buckets[quail::Hash<K>::DoHash(key) % BUCKET_SIZE];
		while (buck)
		{
			if (buck->key == key)
				return buck;
			else
				buck = buck->next;
		}
		return 0;
	}
};


int main()
{
#ifdef FAKE_WEAR_LEVELING
	MyAlloactor::addr = (char*)mmap(nullptr, MAX_ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
#else
	MyAlloactor::addr = (char*)QuailAlloc(MAX_ALLOC_SIZE - 8);
	auto counters = QuailGetCounters();
#endif
	typedef HashMap<uint64_t, uint64_t, MyAlloactor> HMap;
	HMap *mymap = new (MyAlloactor::alloc(sizeof(HMap)))HMap();

	std::mt19937 gen{ 1234 };
	const int MAX_IDX = 0xffff;
	std::normal_distribution<> d{ MAX_IDX / 2,MAX_IDX / 4 };

	for (int n = 0; n < 10000; ++n) {
		uint64_t idx = (uint64_t)std::round(d(gen)) % MAX_IDX;
		mymap->Set(idx, n);
	}
	int cnt_sum = 0;
#ifdef FAKE_WEAR_LEVELING
	for (int i = 0; i < MyAlloactor::cur_len / ALLOCATOR_BYTES_PER_BIT; i++)
	{
		cnt_sum += counts[i];
		printf("Page %d = %d\n", i, counts[i]);
	}
#else
	
	for (int i = 0; i < NVM_SIZE_IN_BYTES / ALLOCATOR_BYTES_PER_BIT; i++)
	{
		if (counters[i])
		{
			cnt_sum += counters[i];
			printf("Page %d = %d\n", i, counters[i].load());
		}
	}
#endif
	printf("Total = %d\n", cnt_sum);
}
/*
void print_map()
{
	FILE* f = fopen("/proc/self/maps", "r");
	char buf[1000] = { 0 };
	while (!feof(f))
	{
		fgets(buf, 999, f);
		printf("%s",buf);
	}
	fclose(f);
}


int main()
{
	size_t* buf0 = (size_t*) QuailAlloc(9000);
	size_t* buf = (size_t*)QuailAlloc(9000);
	QuailFree(buf0);
	//printf("===================Before write\n");
	//print_map();
	fprintf(stderr, "Alloc buffer %p\n", buf);
	buf[1002] = 314;
	for (int i = 0; i < 1200; i++)
	{
		buf[1000] = 23;
	}
	fprintf(stderr, "===================After write\n");
	assert(buf[1002] == 314);
	buf[999] = 123;
	//print_map();
	for (int i = 0; i < 1200; i++)
	{
		buf[1000] = 23;
	}
	fprintf(stderr, "===================After write2\n");
	assert(buf[1002] == 314);
	assert(buf[999] == 123);
	print_map();
	QuailFree(buf);
	//print_map();
}*/