//#include <stddef.h>
#include <sys/types.h>
#include <stdio.h>
#include <dlfcn.h>
//#include "HookFunction.h"
//def_name(read);

/*auto my_read = [](int fd, void *buf, size_t nbytes) -> ssize_t
{

	fprintf(stderr, "read\n");
	return CallOld(Name_read(), ssize_t(), fd, buf, nbytes);
};
(=*/
extern "C" ssize_t read(int fd, void *buf, size_t nbytes)
{
	fprintf(stderr, "read\n");
	return 0;
	//return CallHooked(Name_read(),my_read, ssize_t(), fd, buf, nbytes);
}


int main()
{
	printf("addr %p", dlsym(RTLD_NEXT, "read"));
	fflush(stdout);
	return 0;
}