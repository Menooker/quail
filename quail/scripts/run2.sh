#ulimit -c unlimited
export LD_PRELOAD=$(pwd)/bin/libquail2.so
echo $LD_PRELOAD
export QUAIL_OUTPUT=./out/gcc_soft.txt
time g++ -I./third_party/include -c quail.cpp -std=c++11 -g -O0 -o quail_test.o
#bin/qtest
#find /home/
