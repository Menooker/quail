#pragma once
#include <stdint.h>
#include <algorithm>
#include <array>
#include <math.h>
namespace quail
{
	namespace CMSHashFunc
	{
		////https://stackoverflow.com/a/12996028
		static inline unsigned Hash64_1(uint64_t v)
		{
			uint64_t x = v;
			x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
			x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
			x = x ^ (x >> 31);
			return x;
		}
		static inline unsigned Hash64_2(uint64_t v)
		{
			uint64_t x = v;
			x = (x ^ (x >> 32));
			x = (x ^ (x >> 16));
			return x;
		}

		//https://stackoverflow.com/a/6867612/4790873
		static inline unsigned Hash64_3(uint64_t u)
		{
			uint64_t v = u * 3935559000370003845 + 2691343689449507681;

			v ^= v >> 21;
			v ^= v << 37;
			v ^= v >> 4;

			v *= 4768777513237032717;

			v ^= v << 20;
			v ^= v >> 41;
			v ^= v << 5;

			return v;
		}
	}

	template<typename _CounterT, unsigned _SIZE>
	class CMSCounter
	{
		std::array<_CounterT,_SIZE> counters;
	public:
		void Reset()
		{
			std::fill(counters.begin(), counters.end(), 0);
		}
		CMSCounter()
		{
			Reset();
		}
		void Put(uintptr_t itm)
		{
			counters[CMSHashFunc::Hash64_1(itm) % _SIZE]++;
			counters[CMSHashFunc::Hash64_2(itm) % _SIZE]++;
			counters[CMSHashFunc::Hash64_3(itm) % _SIZE]++;
		}
		float Similarity(const CMSCounter<_CounterT, _SIZE>& other) 
		{
			auto inner = std::inner_product(counters.begin(), counters.end(), other.counters.begin(), 0.0f);
			auto bin_op= [](float left, float right)->float {
				return left + right * right;
			};
			auto mod1 = std::accumulate(counters.begin(), counters.end(), 0.0f, bin_op);
			auto mod2 = std::accumulate(other.counters.begin(), other.counters.end(), 0.0f, bin_op);
			//fprintf(stderr, "this=%p other=%p\n", this, &other);
			//fprintf(stderr, "inner=%f,m1=%f,m2=%f ", inner, mod1, mod2);
			return inner / sqrtf(mod1) / sqrtf(mod2);
		}
		uint64_t Count(uintptr_t itm)
		{
			return std::min({ counters[CMSHashFunc::Hash64_1(itm) % _SIZE],
				counters[CMSHashFunc::Hash64_2(itm) % _SIZE],
				counters[CMSHashFunc::Hash64_3(itm) % _SIZE] });
		}
	};
}