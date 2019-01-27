#include <cstdio>
#include <unistd.h>  
#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include <iomanip>
#include <string>
#include <map>
#include <random>
#include <cmath>
#include <sys/mman.h>

using namespace std::chrono;




int main()
{
	std::mt19937 gen{ 1234 };
	const size_t PageSize = 4096;
	const int PAGES = 10;
	const int MAX_IDX = PAGES * PageSize / sizeof(int);
	const int COUNT_PER_PAGE = PageSize / sizeof(int);
	int* a = (int*)mmap(nullptr, sizeof(int)*MAX_IDX, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	int counts[PAGES] = { 0 };
	std::normal_distribution<> d{ MAX_IDX/2,MAX_IDX/4 };

	for (int n = 0; n<1000000; ++n) {
		int idx = (int)std::round(d(gen))% MAX_IDX;
		if (idx < 0)
			idx += MAX_IDX;
		a[idx] = n;
		++counts[idx/ COUNT_PER_PAGE];

	}
	/*for (int i = 0; i < PAGES;i++) {
		std::cout << std::setw(2)
			<< i << ' ' << std::string(counts[i]/100 , '*') << ' '<< counts[i] << '\n';
	}*/
	for (int i = 0; i < PAGES; i++) {
		std::cout << (int*)((char*)a+i* PageSize) << ' ' << counts[i] << '\n';
	}
}

