# DNS Proxy Filter Server
# Copyright (c) 2010-2019 Untangle, Inc.
# All Rights Reserved
# Written by Michael A. Hotz

VERSION = 1.0.0
DEBUG = -g3 -ggdb
#GPROF = -pg
#SPEED = -O2

BUILDID := "$(shell date -u "+%G/%m/%d %H:%M:%S UTC")"
SYSTEM := $(shell uname)

CPPFLAGS = $(DEBUG) $(GPROF) $(SPEED) -Wall
#CPPFLAGS = $(DEBUG) $(GPROF) $(SPEED) -Wall -Wno-deprecated -pthread

CXXFLAGS += -DVERSION=\"$(VERSION)\"
CXXFLAGS += -DBUILDID=\"$(BUILDID)\"

OBJFILES := $(patsubst %.cpp,%.o,$(wildcard *.cpp))
LIBFILES = -lpthread -lrt -lmysqlclient

dnsproxy : $(OBJFILES)
	$(CXX) $(DEBUG) $(GPROF) $(SPEED) $(CPU) $(OBJFILES) $(LIBFILES) -o dnsproxy

$(OBJFILES) : Makefile *.h

clean : force
	rm -r -f Debug
	rm -f dnsproxy
	rm -f gmon.out
	rm -f *.vtg
	rm -f *.o

force :
