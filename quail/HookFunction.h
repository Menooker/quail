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
	typedef typename TName::func_wrapper::ptrFunc ptrFunc;
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

#define def_name(_name,_ret_type,...) struct Name_##_name{ static constexpr char const* name = #_name;typedef _ret_type return_type; typedef OldFuncWrapper<Name_##_name,_ret_type,__VA_ARGS__> func_wrapper;};
#define get_name(_name) Name_##_name;

template <typename TName, typename... TTypes>
typename TName::return_type CallOld(TTypes... args)
{
	return TName::func_wrapper::old_func(std::forward<TTypes>(args)...);
}

template <typename TName, typename TFunc, typename... TTypes>
typename TName::return_type CallHooked(TFunc func, TTypes... args)
{
	return HookFunction<TName, TFunc, typename TName::return_type, TTypes...>::Func(std::forward<TTypes>(args)...);
}


template <typename TName, typename TRet, typename... TTypes>
typename OldFuncWrapper<TName, TRet, TTypes...>::ptrFunc OldFuncWrapper<TName, TRet, TTypes...>::old_func = nullptr;

template <typename TName>
void DoHook(typename TName::func_wrapper::ptrFunc replacement_func)
{
	HookStatus ret;
	if ((ret = HookIt(dlsym(RTLD_NEXT, TName::name), (void**)&TName::func_wrapper::old_func, (void*)replacement_func)) != 0)
	{
		fprintf(stderr, "Hook error %d\n", ret);
		exit(1);
	}
}
