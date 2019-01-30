#pragma once
#include <vector>
#include <stdint.h>
#include <stdlib.h>
namespace quail
{
	constexpr uintptr_t all_one = (~(uintptr_t)0);
	constexpr uintptr_t number_of_bits_per_cell = sizeof(uintptr_t) * 8;

	inline size_t divide_and_ceil(size_t x, size_t y)
	{
		return 1 + ((x - 1) / y);
	}

	class BitSet
	{
		std::vector<uintptr_t> bset;
		static bool Get(const std::vector<uintptr_t>::iterator& cell, size_t off)
		{
			uintptr_t& oldv = *cell;
			return oldv & (((uintptr_t)1) << off);
		}
	public:
		BitSet(size_t sz)
		{
			auto real_sz = divide_and_ceil(sz, number_of_bits_per_cell);
			bset = std::vector<uintptr_t>(real_sz, 0);
		}
		void Set(size_t idx, bool v)
		{
			auto real_idx = idx / number_of_bits_per_cell;
			auto offset = idx % number_of_bits_per_cell;
			auto& oldv = bset[real_idx];
			oldv &= ~( ((uintptr_t)1) << offset);
			uintptr_t v2 = v;
			oldv |= (v2 << offset);
		}
		void Set(size_t idx)
		{
			auto real_idx = idx / number_of_bits_per_cell;
			auto offset = idx % number_of_bits_per_cell;
			auto& oldv = bset[real_idx];
			oldv |= ((uintptr_t)1 << offset);
		}
		void Clear(size_t idx)
		{
			auto real_idx = idx / number_of_bits_per_cell;
			auto offset = idx % number_of_bits_per_cell;
			auto& oldv = bset[real_idx];
			oldv &= ~(((uintptr_t)1) << offset);
		}

		void RangeSet(size_t idx, size_t len)
		{
			for (int i = 0; i < len; i++)
			{
				Set(idx + i);
			}
		}
		void RangeClear(size_t idx, size_t len)
		{
			for (int i = 0; i < len; i++)
			{
				Clear(idx + i);
			}
		}

	

		bool Get(size_t idx)
		{
			auto real_idx = idx / number_of_bits_per_cell;
			auto offset = idx % number_of_bits_per_cell;
			return Get(bset.begin() + real_idx, offset);
		}

		class iterator
		{
		public:
			typedef iterator self_type;
			typedef bool value_type;
			//typedef bool& reference;
			//typedef bool* pointer;
			typedef std::forward_iterator_tag iterator_category;
			typedef int difference_type;
			std::vector<uintptr_t>::iterator idx;
			size_t offset;

			void forward()
			{
				offset++;
				if (offset >= number_of_bits_per_cell)
				{
					offset = 0;
					idx++;
				}
			}
			iterator() : offset(0) { }
			iterator(std::vector<uintptr_t>::iterator idx,size_t offset) : idx(idx),offset(offset) { }
			self_type operator++() {
				self_type i = *this;
				forward();
				return i;
			}
			size_t operator-(const self_type& rhs)
			{
				return (idx - rhs.idx)*number_of_bits_per_cell + offset - rhs.offset;
			}
			self_type operator++(int junk) { forward(); return *this; }
			value_type operator*() { return BitSet::Get(idx,offset); }
			bool operator==(const self_type& rhs) { return idx == rhs.idx && offset == rhs.offset; }
			bool operator!=(const self_type& rhs) { return !(operator==(rhs)); }
		};

		iterator begin()
		{
			return iterator(bset.begin(), 0);
		}
		iterator end()
		{
			return iterator(bset.end(), 0);
		}


	};
}