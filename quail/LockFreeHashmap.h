#pragma once
#include <atomic>
#include <cstdint>
#include <string.h>
//#include <stdio.h>
namespace quail
{
	struct Alloactor
	{
		void* alloc(size_t z)
		{
			return malloc(z);
		}
		void release(void* ptr, size_t z)
		{
			free(ptr);
		}
	};

	template<typename Key>
	struct Hash
	{

	};


	template<>
	struct Hash<uint64_t>
	{
		//https://stackoverflow.com/a/12996028
		static unsigned DoHash(const uint64_t& v)
		{
			uint64_t x = v;
			x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
			x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
			x = x ^ (x >> 31);
			return x;
		}
	};


	template<>
	struct Hash<void*>
	{
		static unsigned DoHash(const void* & v)
		{
			return Hash<uintptr_t>::DoHash((uintptr_t)v);
		}
	};

	//based on the blog
	//http://blog.csdn.net/sefler/article/details/8779559
	template<int BucketSize, typename Key, typename Value, typename Alloc=Alloactor>
	class LockFreeHashmap
	{
	public:
		Value find(const Key& key)
		{
			unsigned bucketid = Hash<Key>::DoHash(key);
			return _find(bucket[bucketid % BucketSize], key);
		}

		void insert(const Key& key, const Value& value)
		{
			unsigned bucketid = Hash<Key>::DoHash(key);
			return _insert(bucket[bucketid % BucketSize], key, value);
		}

		Value insert_if_absent(const Key& key, const Value& value)
		{
			std::atomic<Node*>* prev;
			Node* cur;
			Node* new_node=nullptr;
			uint32_t index;

			index = Hash<Key>::DoHash(key) % BucketSize;
			while (1)
			{
				if (_find(bucket[index], key, prev, cur) != 0)
				{
					if (new_node)
						alloactor.release(new_node, sizeof(Node));
					return cur->value;
				}

				if (!new_node)
				{
					new_node = (Node*)alloactor.alloc(sizeof(Node));
					new_node->value = value;
					new_node->key = key;
				}
				new_node->next.store(*prev);

				if (prev->compare_exchange_weak(cur, new_node))
				{
					break;
				}
			}

			return 0;
		}

		/*
		Iterate on each of the Key-Value pair.
		f should have a signature: bool f(const Key&, const Value&) 
		*/
		template<typename Functor>
		void foreach(Functor f)
		{
			for (int i = 0; i < BucketSize; i++)
			{
				Node* next = bucket[i];
				while (next)
				{
					if (!f(next->key, next->value))
					{
						return;
					}
					next = next->next;
				}
			}
		}

/*		void stat()
		{
			for (int i = 0; i < BucketSize; i++)
			{
				int cnt = 0;
				Node* next = bucket[i];
				while (next)
				{
					cnt++;
					next = next->next;
				}
				if(cnt>=3)printf("Bucket %d - %d\n", i, cnt);
			}
		}*/

		LockFreeHashmap()
		{
			memset(bucket, 0, sizeof(bucket));
		}
	private:

		Alloc alloactor; 
		struct Node
		{
			Value value;
			Key key;
			std::atomic<Node*> next;
		};

		std::atomic<Node*> bucket[BucketSize];

		Value _find(std::atomic<Node*>& head, Key key)
		{
			std::atomic<Node*>* prev;
			Node* cur;
			return _find(head, key, prev, cur);
		}

		Value _find(std::atomic<Node*>&  head, Key key, std::atomic<Node*>* &prev,Node* &cur)
		{
			
			std::atomic<Node*>* next;
			Value cvalue;
			Key ckey;

			while (1)
			{
				prev = &head;
				cur = head;

				while (1)
				{
					if (cur == NULL)
					{
						return 0;
					}

					next = &cur->next;
					ckey = cur->key;
					cvalue = cur->value;

					if (*prev != cur)
					{
						break; // The list has been modified, start over  
					}

					if (key >= ckey)
					{
						return key == ckey ? cvalue : 0;
					}

					// else keep looking  
					prev = next;
					cur = *next;
				}
			}
		}

		void _insert(std::atomic<Node*>& head, const Key& key, const Value& value)
		{
			Node* new_entry = (Node*)alloactor.alloc(sizeof(Node));
			new_entry->key = key;
			new_entry->value = value;

			// use CAS to enablelock free   
			while (1)
			{
				std::atomic<Node*>* prev = &head;
				Node* cur = head;
				while (cur != NULL && key < cur->key)
				{
					prev = &cur->next;
					cur = cur->next;
				}
				new_entry->next.store(*prev);
				if (prev->compare_exchange_weak(cur, new_entry))
				{
					break;
				}

				cur = *prev;
			}
		}
	};



}