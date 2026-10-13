# owfuzz
#
# Copyright (C) 2020 E7mer <haimohk@gmail.com>
#

export TOP_PATH CXX CC LD CCLD LDFLAGS CFLAGS CXXFLAGS CPPFLAGS LIBS KSLIBS PTHREADLIBS NETLINKLIBS KISMETWIFI OSDEPWIFI LIBMLIB

CFLAGS+= -g

SUBDIRS = frames common procedures protocols

# Discover frame implementations so an added builder needs no linker-list edit.
FRAMEOBJ = $(patsubst %.c,%.o,$(wildcard common/*.c frames/*.c frames/*/*.c)) \
    procedures/direct/direct.o procedures/awdl/awdl.o procedures/awdl/awdl_frame.o \
    procedures/awdl/wire.o procedures/mesh/mesh.o

PROTOCOL_OBJS = protocols/protocol.o protocols/cli.o protocols/generated_registry.o $(patsubst %.c,%.o,$(wildcard protocols/modules/*.c))

OBJS = owfuzz.o fuzz_control.o hashtable.o $(PROTOCOL_OBJS)

all: subdir
	$(MAKE) owfuzz

subdir:
	@for dir in $(SUBDIRS); \
		do $(MAKE) -C $$dir || exit 1; \
	done \

owfuzz: $(OBJS) $(FRAMEOBJ)
	$(CC) $(OBJS) $(FRAMEOBJ) $(CFLAGS) -o $(@) $(KISMETWIFI) $(OSDEPWIFI) $(LIBMLIB) $(PTHREADLIBS) $(NETLINKLIBS)

rmsym:
	strip -g owfuzz
	strip -s owfuzz
	strip --remove-section=.symtab owfuzz
	#strip --remove-section=.dynsym owfuzz


.PHONY : clean
clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit 1; \
	done \

	rm -f *.o *.so *.a *~ owfuzz

.PHONY: all subdir
