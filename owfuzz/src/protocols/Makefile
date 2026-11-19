CC ?= cc
PYTHON ?= python3
MODULES := $(wildcard modules/*.c)
OFFLINE_MODULES := $(filter-out modules/wifi_legacy.c,$(MODULES))
STRICT := -std=c99 -Wall -Wextra -Werror -pedantic
all: $(MODULES:.c=.o) protocol.o cli.o generated_registry.o

generated_registry.c: FORCE $(MODULES) ../../../tools/generate_protocol_registry.py Makefile
	$(PYTHON) ../../../tools/generate_protocol_registry.py $@ $(MODULES)

build/offline_registry.c: FORCE $(OFFLINE_MODULES) ../../../tools/generate_protocol_registry.py Makefile
	$(PYTHON) ../../../tools/generate_protocol_registry.py $@ $(OFFLINE_MODULES)

build/owfuzz-protocol: protocol.c cli.c protocol.h $(OFFLINE_MODULES) build/offline_registry.c
	$(CC) $(STRICT) -DOW_STANDALONE -I. protocol.c cli.c $(OFFLINE_MODULES) build/offline_registry.c -o $@

offline: build/owfuzz-protocol

build/test_protocol: test_protocol.c protocol.c protocol.h $(OFFLINE_MODULES) build/offline_registry.c
	$(CC) $(STRICT) -I. test_protocol.c protocol.c $(OFFLINE_MODULES) build/offline_registry.c -o $@

test: build/test_protocol build/owfuzz-protocol
	./build/test_protocol
	$(PYTHON) test_cli.py ./build/owfuzz-protocol
	$(PYTHON) test_legacy.py
	$(PYTHON) ../../../tools/test_extension_metrics.py

.PHONY: all offline test clean FORCE
FORCE:

$(MODULES:.c=.o) protocol.o cli.o generated_registry.o: protocol.h
clean:
	rm -f *.o modules/*.o generated_registry.c build/offline_registry.c build/owfuzz-protocol build/test_protocol
