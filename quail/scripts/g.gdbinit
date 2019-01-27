	file /usr/lib/gcc/x86_64-linux-gnu/5/cc1plus
	set args -quiet -imultiarch x86_64-linux-gnu -D_GNU_SOURCE read.cpp -quiet -dumpbase read.cpp -mtune=generic -march=x86-64 -auxbase-strip quail_test.o -g -O0 -std=c++11
	set env LD_PRELOAD=/mnt/d/Menooker/CXX/quail/quail/bin/libquail.so 
	set env QUAIL_CAPTURE_ALL=1 
	handle SIGSEGV noignore nostop noprint 
# handle SIGTRAP noignore nostop noprint
	run
