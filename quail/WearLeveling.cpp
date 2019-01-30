#include <stdint.h>
#include <sys/unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <map>
#include <assert.h>
#include <string.h>
#include <vector>
#include "util.h"


#define COMPILE_WL_TESTS 1

uint64_t NVM_SIZE_IN_BYTES = (32 * 1024);

extern size_t PageSize;

constexpr int ALLOCATOR_BYTES_PER_BIT = 4096;
constexpr uint64_t HEAP_CHECK_MAGIC = 0x12345678521641aa;
constexpr int EXTRA_ALLOC_SIZE = sizeof(size_t)*2;



struct NVMManager
{
	std::vector<char> allocator_bitmap;
	std::vector<char>::iterator itr;
	int fd;
	NVMManager& operator = (NVMManager&) = delete;
	NVMManager& operator = (const NVMManager&) = delete;
	NVMManager() :allocator_bitmap(NVM_SIZE_IN_BYTES / ALLOCATOR_BYTES_PER_BIT)
	{
		int fd = open("mapfile.dat", O_RDWR, 0666);
		if (fd == -1)
		{
			perror("oper file failed: ");
			exit(0);
		}
		itr = allocator_bitmap.begin();
	}

#ifdef COMPILE_WL_TESTS
	NVMManager(int) //only for testing
	{
	}
#endif

	struct MemChunkInfo
	{
		size_t len;
		size_t offset;
		bool IsLeftOf(void* ths_ptr, const MemChunkInfo& other, void* other_ptr) const
		{
			if (offset + len != other.offset)
				return false;
			if ((char*)ths_ptr + len != (char*)other_ptr)
				return false;
			return true;
		}
		bool IsRightOf(void* ths_ptr, const MemChunkInfo& other, void* other_ptr) const
		{
			return other.IsLeftOf(other_ptr, *this, ths_ptr);
		}
		bool operator== (const MemChunkInfo& other) const
		{
			return len == other.len && offset == other.offset;
		}
	};
	std::map<void*, MemChunkInfo> ptr_to_file_offset;

	void SplitMemChunk(void* ptr, size_t len, size_t offset)
	{
		//first find the chunk where ptr is
		auto itr = ptr_to_file_offset.lower_bound(ptr);
		if (itr != ptr_to_file_offset.end() && itr->first == ptr)
		{
			//do nothing
		}
		else if (itr != ptr_to_file_offset.begin())
		{
			--itr;
		}
		assert(itr->first <= ptr &&
			((char*)itr->first + itr->second.len >= (char*)ptr + len));
		//split the chunk into 3 (maybe 2) smaller chunks
		//calculate the right & left hand side chunk
		size_t lhs_len = (char*)ptr - (char*)itr->first;
		size_t rhs_len = itr->second.len - lhs_len - len;
		size_t rhs_offset = itr->second.offset + lhs_len + len;
		std::map<void*, MemChunkInfo>::iterator middle_itr;
		if (itr->first != ptr)
		{
			itr->second.len = lhs_len;
			ptr_to_file_offset.insert(std::make_pair(ptr, MemChunkInfo{ len,offset }));
			middle_itr = ptr_to_file_offset.find(ptr);
		}
		else
		{
			itr->second.len = len;
			itr->second.offset = offset;
			middle_itr = itr;
		}
		if (rhs_len)
		{
			void* rhs_ptr = (char*)ptr + len;
			ptr_to_file_offset.insert(std::make_pair(rhs_ptr, MemChunkInfo{ rhs_len,rhs_offset }));
		}
		MergeMemChunks(middle_itr);
	}

	void MergeMemChunks(std::map<void*, MemChunkInfo>::iterator itr)
	{
		while (itr != ptr_to_file_offset.begin())
		{
			auto prev = std::prev(itr);
			if (prev->second.IsLeftOf(prev->first, itr->second, itr->first))
			{
				prev->second.len += itr->second.len;
				ptr_to_file_offset.erase(itr);
			}
			else
			{
				break;
			}
			itr = prev;
		}
		for(;;)
		{
			auto nxt = std::next(itr);
			if (nxt == ptr_to_file_offset.end())
				break;
			if (itr->second.IsLeftOf(itr->first, nxt->second, nxt->first))
			{
				itr->second.len += nxt->second.len;
				ptr_to_file_offset.erase(nxt);
			}
			else
			{
				break;
			}
		}
	}
};

static NVMManager& GetManager()
{
	static NVMManager mgr;
	return mgr;
}

//swap one page (ptr) with a "page" in NVM with given offset
extern "C" void QuailSwap(void* ptr, size_t offset)
{
	auto& mgr = GetManager();
	//first mmap the NVM to a temp location
	char* mmapret = (char*)mmap(nullptr, PageSize, PROT_WRITE | PROT_READ, MAP_SHARED, mgr.fd, offset);
	assert(mmapret != (char*)-1);
	//move the data
	memcpy(mmapret, ptr, PageSize);
	//unmap the temp location
	auto ret = munmap(mmapret, PageSize);
	assert(ret != -1);
	//unmap the old NVM
	ret = munmap(ptr, PageSize);
	//re-mmap the NVM with new physical location
	mmapret = (char*)mmap(ptr, PageSize, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_FIXED, mgr.fd, offset);
	assert(mmapret == ptr);
	mgr.SplitMemChunk(ptr, PageSize, offset);
}


extern "C" void QuailFree(void* ptr)
{
	uint64_t* header;
	assert(header[-1] == HEAP_CHECK_MAGIC);
	uint64_t sz = header[-2];
	char* real_ptr = (char*) (&header[-2]);
	assert((uintptr_t)real_ptr % PageSize == 0);
	int64_t remaining = sz;
	auto& mgr = GetManager();
	auto itr = mgr.ptr_to_file_offset.find(real_ptr);
	assert(itr != mgr.ptr_to_file_offset.end());
	for(;;)
	{
		std::fill(mgr.allocator_bitmap.begin() + itr->second.offset / ALLOCATOR_BYTES_PER_BIT,
			mgr.allocator_bitmap.begin() + (itr->second.offset + itr->second.len) / ALLOCATOR_BYTES_PER_BIT,
			0);
		remaining -= itr->second.len;
		assert(remaining >= 0);
		if (remaining == 0)
			break;
		void* expect_next_ptr = (char*)itr->first + itr->second.len;
		itr = mgr.ptr_to_file_offset.erase(itr);
		assert(itr->first == expect_next_ptr);
	}
	auto ret = munmap(ptr, sz);
	assert(ret != -1);
}

extern "C" void* QuailAlloc(size_t sz)
{
	sz += EXTRA_ALLOC_SIZE;
	auto find_num = divide_and_ceil(sz, ALLOCATOR_BYTES_PER_BIT);
	auto& mgr = GetManager();
	
	auto itr = mgr.itr;
	std::vector<char>::iterator start_itr;
	auto find_itr = [&itr,&mgr,find_num, &start_itr]()
	{
		size_t found = 0;
		for (; itr != mgr.allocator_bitmap.end(); ++itr)
		{
			if (!*itr)
			{
				if (found == 0)
					start_itr = itr;
				found++;
				if (found == find_num)
				{
					++itr;
					mgr.itr = itr;
					return true;
				}
			}
			else
			{
				found = 0;
			}
		}
		return false;
	};
	
	if (!find_itr()) //if searching from current location fails, search again from the beginning
	{
		itr = mgr.allocator_bitmap.begin();
		if (!find_itr())
			return nullptr;
	}
	//set the allocated memory bitmap to 1
	std::fill(start_itr, itr, 1);
	size_t offset = (start_itr - mgr.allocator_bitmap.begin()) * ALLOCATOR_BYTES_PER_BIT;
	size_t* mmapret = (size_t*)mmap(nullptr, ALLOCATOR_BYTES_PER_BIT * find_num, PROT_WRITE | PROT_READ, MAP_SHARED, mgr.fd, offset);
	assert(mmapret != (size_t*)-1);
	*mmapret = ALLOCATOR_BYTES_PER_BIT * find_num;
	*(mmapret + 1) = HEAP_CHECK_MAGIC;
	mgr.ptr_to_file_offset[mmapret] = { ALLOCATOR_BYTES_PER_BIT * find_num, offset };
	return mmapret + 2;
}



#ifdef COMPILE_WL_TESTS
#define VOID_(a) ((void*)a)
size_t PageSize = 4096;
int main()
{
	NVMManager mgr(1);
	mgr.ptr_to_file_offset = {
	{VOID_(100),{100,0}},
	{VOID_(200),{100,1000}},
	{VOID_(300),{100,200}}
	};
	typedef decltype(mgr.ptr_to_file_offset) mymap;
	mgr.SplitMemChunk(VOID_(200), 100, 100);
	assert(mgr.ptr_to_file_offset == mymap({
	{VOID_(100),{300,0}},
		}));

	mgr.ptr_to_file_offset.clear();
	mgr.ptr_to_file_offset = {
	{VOID_(0),{50,2000}},
	{VOID_(100),{100,0}},
	{VOID_(200),{100,1000}},
	{VOID_(300),{100,200}}
	};
	mgr.SplitMemChunk(VOID_(200), 100, 100);
	assert(mgr.ptr_to_file_offset == mymap({
	{VOID_(0),{50,2000}},
	{VOID_(100),{300,0}},
		}));
	mgr.ptr_to_file_offset.clear();

	mgr.ptr_to_file_offset = {
	{VOID_(0),{50,2000}},
	{VOID_(100),{300,0}},
	};
	mgr.SplitMemChunk(VOID_(200), 100, 1000);
	assert(mgr.ptr_to_file_offset == mymap({
	{VOID_(0),{50,2000}},
	{VOID_(100),{100,0}},
	{VOID_(200),{100,1000}},
	{VOID_(300),{100,200}}
		}));
	mgr.ptr_to_file_offset.clear();


	mgr.ptr_to_file_offset = {
	{VOID_(0),{100,2000}},
	{VOID_(100),{300,0}},
	};
	mgr.SplitMemChunk(VOID_(100), 100, 500);
	assert(mgr.ptr_to_file_offset == mymap({
	{VOID_(0),{100,2000}},
	{VOID_(100),{100,500}},
	{VOID_(200),{200,100}},
		}));
	mgr.ptr_to_file_offset.clear();

	mgr.ptr_to_file_offset = {
	{VOID_(0),{100,400}},
	{VOID_(100),{300,0}},
	};
	mgr.SplitMemChunk(VOID_(100), 100, 500);
	assert(mgr.ptr_to_file_offset == mymap({
	{VOID_(0),{200,400}},
	{VOID_(200),{200,100}},
		}));
	mgr.ptr_to_file_offset.clear();


	mgr.ptr_to_file_offset = {
	{VOID_(0),{100,400}},
	{VOID_(100),{300,0}},
	{VOID_(400),{100,4000}},
	};
	mgr.SplitMemChunk(VOID_(300), 100, 500);
	assert(mgr.ptr_to_file_offset == mymap({
	{VOID_(0),{100,400}},
	{VOID_(100),{200,0}},
	{VOID_(300),{100,500}},
	{VOID_(400),{100,4000}},
		}));
	mgr.ptr_to_file_offset.clear();

	mgr.ptr_to_file_offset = {
	{VOID_(0),{100,400}},
	{VOID_(100),{300,0}},
	{VOID_(400),{100,600}},
	};
	mgr.SplitMemChunk(VOID_(300), 100, 500);
	assert(mgr.ptr_to_file_offset == mymap({
	{VOID_(0),{100,400}},
	{VOID_(100),{200,0}},
	{VOID_(300),{200,500}},
		}));
	mgr.ptr_to_file_offset.clear();

}

#endif