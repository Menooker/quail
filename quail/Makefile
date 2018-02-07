.PHONY: test

PWD_DIR=$(shell pwd)
CXX ?= g++
CXXFLAGS ?= -std=c++11 -g -O2 -I$(PWD_DIR)/third_party/include -L$(PWD_DIR)/third_party/bin/
LIBS ?= -lpthread

qtest: main.o Interpreter.o
	$(CXX) -o bin/$@ $(CXXFLAGS) -Wl,--start-group $^  $(LIBS) -lZydis -Wl,--end-group 
quail.o: quail.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS) 
user_hooks.o: user_hooks.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS) 
soft_dirty.o: soft_dirty.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS) 
inline_hook.o: inline_hook.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS)	
Interpreter.o: Interpreter.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS)	
lib : quail.o user_hooks.o inline_hook.o Interpreter.o
	$(CXX) -fPIC $(CXXFLAGS) -shared -o bin/libquail.so  -Wl,--start-group $^ $(LIBS) -lZydis -ldl -Wl,--end-group 
lib2 : user_hooks.o soft_dirty.o
	$(CXX) -fPIC $(CXXFLAGS) -shared -o bin/libquail2.so  -Wl,--start-group $^ $(LIBS) -ldl -Wl,--end-group 
lib3 : read.o
	$(CXX) -fPIC $(CXXFLAGS) -shared -o bin/libquail3.so  -Wl,--start-group $^ $(LIBS) -ldl -Wl,--end-group 
clean:
	rm -f *.o
	rm -f bin/qtest
remake: clean qtest

