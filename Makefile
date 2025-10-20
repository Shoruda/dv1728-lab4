# Simple Makefile for mycurl

## Adjust CXX/CXXFLAGS and SRC to fit if your doing C or C++. 

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS  :=
LDLIBS   := -lssl -lcrypto
TARGET   := mycurl
SRC      := mycurl.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(TARGET) $(TARGET2)

.PHONY: all clean
