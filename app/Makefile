APP = oceanus

SRCS := $(wildcard *.c)
LIBOCEANUS := oceanus
OCEANUS_DIR := ..
LIBOCEANUS_DIR := $(OCEANUS_DIR)/build
LDFLAGS := -L$(LIBOCEANUS_DIR) -l$(LIBOCEANUS)
CC := gcc
CFLAGS := -O3 -I$(OCEANUS_DIR)/include

PHONY := all
all: $(APP)

$(APP): $(SRCS) $(LIBOCEANUS_DIR)/lib$(LIBOCEANUS).so
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

$(LIBOCEANUS_DIR)/lib$(LIBOCEANUS).so: FORCE
	make -C $(OCEANUS_DIR) so

PHONY += FORCE
FORCE:;

PHONY += run
run: $(APP)
	export LD_LIBRARY_PATH=$(shell pwd)/$(LIBOCEANUS_DIR):$(LD_LIBRARY_PATH) && ./oceanus

PHONY += clean
clean:
	rm -f $(APP)

PHONY += distclean
distclean:
	rm -f $(APP)
	make -C $(OCEANUS_DIR) clean

.PHONY: $(PHONY)
