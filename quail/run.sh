ulimit -S unlimited
export LD_PRELOAD=$(pwd)/bin/libquail.so
echo $LD_PRELOAD
time g++ -c quail.cpp  -std=c++11 -g -O0 -o quail_test.o
#/usr/lib/gcc/x86_64-linux-gnu/5/cc1plus -quiet -imultiarch x86_64-linux-gnu -D_GNU_SOURCE quail.cpp -quiet -dumpbase quail.cpp -mtune=generic -march=x86-64 -auxbase-strip quail_test.o -g -O0 -std=c++11
#bin/qtest
#./readtest
