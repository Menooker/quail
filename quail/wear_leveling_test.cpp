#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

extern "C" void QuailFree(void* ptr);
extern "C" void* QuailAlloc(size_t sz);

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
}