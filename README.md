# Quail
Quail is a memory write monitoring library for Linux on x64. You can use this library to sample or watch the writes to the heap memory. Quail uses inline hooks to intercept calls to the memory allocation functions like mmap and malloc, so you don't need to modify you monitored program to find the write counts.

Quail implements three ways of memory monitoring - sampling by soft dirty bits, sampling by write protection and watching by write protection. The first method is implemented in the library "libquail2.so" and the latter two are implemented in the library "libquail.so".

Quail is compiled into shared libraries. You should first set "LD_PRELOAD" to the absolute path to "libquail.so" or "libquail2.so", and then you can run your program to monitor with Quail.

Here is an example to run Quail to monitor "g++" using sampling by write protection:

```shell
export LD_PRELOAD=/PATH/TO/libquail.so
echo $LD_PRELOAD
export QUAIL_OUTPUT=/PATH/TO/OUTPUT/FILE/FOR/WRITE/COUNT
#export QUAIL_CAPTURE_ALL=1 #Uncomment this line to use watching by write protection
time g++ -I./third_party/include -c quail.cpp -std=c++11 -g -O0 -o quail_test.o
```

## Build instructions
Quail depends on Zydis - a Fast and lightweight x86/x86-64 disassembler library, and PFishHook - a inline hook library written by me. 

First, fetch the source code of Quail:
```shell
git clone https://github.com/Menooker/quail
cd quail/quail
make directories
```

Compile Zydis (in quail/quail/third_party):
```shell
cd third_party
git clone https://github.com/zyantific/zydis
cd zydis
git reset --hard 9ec1e0c4d17bf08f17575e25b0c2cf70c5cc879b
mkdir build && cd build
echo "set(CMAKE_C_FLAGS  \"${CMAKE_C_FLAGS} -fPIC\")" >>../CMakeLists.txt
cmake ..
make
cp ZydisExportConfig.h ../include
cp libZydis.a ../../bin/
cp -R ../include/* ../../include/
cd ../../
```

Fetch PFishHook (in quail/quail/third_party):
```shell
git clone https://github.com/Menooker/PFishHook
cd ..
```

You should now in the directory of "quail/quail". Then make PFishHook with Quail:
```shell
make inline_hook
make lib
make lib2
make test
```
Now you can find "libquail.so" and "libquail2.so" in quail/quail/bin.
