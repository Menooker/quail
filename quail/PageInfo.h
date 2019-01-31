#pragma once
#include <atomic>
#include <mutex>
extern bool need_wear_leveling;
struct PageInfo
{
	union {
		std::atomic<uint64_t> _count;
		std::atomic<uint64_t>* _pcount;
	};
	std::atomic<uint64_t>& GetCount()
	{
		if (need_wear_leveling)
			return *_pcount;
		return _count;
	}
	bool unprotected;
	int prot;
	PageInfo(int _prot, bool _unprotected) :prot(_prot), unprotected(_unprotected), _pcount(nullptr)
	{}
};
typedef PageInfo* PPageInfo;