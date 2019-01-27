#ulimit -S unlimited
export LD_PRELOAD=$(pwd)/bin/libquail.so
echo $LD_PRELOAD
export QUAIL_OUTPUT=/dev/null
#export QUAIL_CAPTURE_ALL=1
#strace -f -o strace2.txt g++ -c quail.cpp  -std=c++11 -g -O0 -o quail_test.o
#time g++ test/hello.cpp -std=c++11 -g -O0 -o test/hello
time g++ -I./third_party/include -c quail.cpp -std=c++11 -g -O0 -o quail_test.o 
#time /usr/lib/gcc/x86_64-linux-gnu/5/cc1plus -quiet -imultiarch x86_64-linux-gnu -D_GNU_SOURCE test/hello.cpp -quiet -dumpbase test/hello.cpp -mtune=generic -march=x86-64 -auxbase-strip quail_test.o -g -O0 -std=c++11 -o test/hello.s; as --64 -o test/hello.o test/hello.s; g++ test/hello.o -o test/hello
#/usr/lib/gcc/x86_64-linux-gnu/5/cc1plus -quiet -imultiarch x86_64-linux-gnu -D_GNU_SOURCE test/hello.cpp -quiet -dumpbase test/hello.cpp -mtune=generic -march=x86-64 -auxbase-strip quail_test.o -g -O0 -std=c++11
#bin/qtest
#./readtest
