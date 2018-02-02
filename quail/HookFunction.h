#pragma once
#include <dlfcn.h>

extern bool init_called;

template <typename TName, typename TRet, typename... TTypes>
struct OldFuncWrapper
{
	typedef TRet(*ptrFunc)(TTypes...);
	static ptrFunc old_func;
};

template <typename TName, typename TFunc, typename TRet, typename... TTypes>
struct HookFunction
{
	typedef typename OldFuncWrapper<TName, TRet, TTypes...>::ptrFunc ptrFunc;
	static TRet Func(TTypes... args)
	{
		ptrFunc& old_func = OldFuncWrapper<TName, TRet, TTypes...>::old_func;
		if (!old_func)
		{
			old_func = (ptrFunc)dlsym(RTLD_NEXT, TName::name);
			if (NULL == OldFuncWrapper<TName, TRet, TTypes...>::old_func) {
				fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
			}
		}
		if (!init_called)
		{
			return old_func(std::forward<TTypes>(args)...);
		}
		TFunc& func = *(TFunc*)(nullptr);
		return func(std::forward<TTypes>(args)...);
	}
};




#define def_name(_name) struct Name_##_name{ static constexpr char const* name = #_name; };
#define get_name(_name) Name_##_name;

template <typename TName, typename TRet, typename... TTypes>
TRet CallOld(TName, TRet, TTypes... args)
{
	return OldFuncWrapper<TName, TRet, TTypes...>::old_func(std::forward<TTypes>(args)...);
}

template <typename TName, typename TFunc, typename TRet, typename... TTypes>
TRet CallHooked(TName, TFunc, TRet, TTypes... args)
{
	return HookFunction<TName, TFunc, TRet, TTypes...>::Func(std::forward<TTypes>(args)...);
}


template <typename TName, typename TRet, typename... TTypes>
typename OldFuncWrapper<TName, TRet, TTypes...>::ptrFunc OldFuncWrapper<TName, TRet, TTypes...>::old_func = nullptr;