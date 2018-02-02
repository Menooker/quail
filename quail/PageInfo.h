#pragma once
#include <atomic>
struct PageInfo
{
	std::atomic<uint32_t> count = { 0 };
	bool unprotected;
	int prot;

	PageInfo(int _prot, bool _unprotected) :prot(_prot), unprotected(_unprotected)
	{}
};
typedef PageInfo* PPageInfo;