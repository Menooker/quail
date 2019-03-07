.PHONY: test directories

PWD_DIR=$(shell pwd)
CXX ?= g++
CXXFLAGS ?= -std=c++14 -fPIC -O0 -g -I$(PWD_DIR)/third_party/include -L$(PWD_DIR)/third_party/bin/ -L$(PWD_DIR)/bin/
LIBS ?= -lpthread

default: lib lib2

bin/qtest: main.o Interpreter.o
	$(CXX) -o $@ $(CXXFLAGS) -Wl,--start-group $^  $(LIBS) -lZydis -Wl,--end-group 
quail.o: quail.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS) 
user_hooks.o: user_hooks.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS) 
soft_dirty.o: soft_dirty.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS) 
Interpreter.o: Interpreter.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS)	
lib : quail.o user_hooks.o  Interpreter.o WearLeveling.o
	$(CXX) -fPIC $(CXXFLAGS) -shared -o bin/libquail.so  -Wl,--start-group $^ $(LIBS) -lPFishHook -ldl -Wl,--end-group 
lib2 : user_hooks.o soft_dirty.o
	$(CXX) -fPIC $(CXXFLAGS) -shared -o bin/libquail2.so  -Wl,--start-group $^ $(LIBS) -lPFishHook -ldl -Wl,--end-group 
faketest: wear_leveling_test.cpp
	$(CXX) -o bin/fake_wear_leveing_test $(CXXFLAGS) -DFAKE_WEAR_LEVELING wear_leveling_test.cpp
test: wear_leveling_test.o lib faketest
	$(CXX) -o bin/wear_leveing_test $(CXXFLAGS) -Wl,--start-group wear_leveling_test.o  $(LIBS) -lquail -Wl,--end-group  -Wl,-rpath='$$ORIGIN'

clean:
	rm -f *.o
	rm -f bin/qtest
remake: clean bin/qtest

inline_hook: directories
	make -C $(PWD_DIR)/third_party/PFishHook LIBPATH=$(PWD_DIR)/third_party/bin INCLUDE=$(PWD_DIR)/third_party/include OUT_DIR=$(PWD_DIR)/third_party/bin OUT_INC_DIR=$(PWD_DIR)/third_party/include

directories:
	mkdir -p $(PWD_DIR)/bin
	mkdir -p $(PWD_DIR)/third_party
	mkdir -p $(PWD_DIR)/third_party/bin
	mkdir -p $(PWD_DIR)/third_party/include
