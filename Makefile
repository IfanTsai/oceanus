ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "Please install libdpdk")
endif

LIB = $(BUILD_DIR)/liboceanus.so

PKGCONF := pkg-config --define-prefix
PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS = -O3 $(shell $(PKGCONF) --cflags libdpdk) -I$(INCLUDE_DIR) -fPIC
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDFLAGS = -shared $(shell $(PKGCONF) --libs libdpdk) -lm -pthread

BUILD_DIR := build
SRC_DIR := src
INCLUDE_DIR := include

LINK_OBJ_DIR := $(BUILD_DIR)/.link_obj
DEP_DIR := $(BUILD_DIR)/.dep

$(shell mkdir -p $(LINK_OBJ_DIR) $(DEP_DIR))

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(addprefix $(LINK_OBJ_DIR)/,$(notdir $(SRCS:.c=.o)))
DEPS := $(addprefix $(DEP_DIR)/,$(notdir $(SRCS:.c=.d)))
LINK_OBJ := $(wildcard $(LINK_OBJ_DIR)/*.o) $(OBJS)

PHONY := all
all: $(DEPS) $(OBJS) $(LIB)

ifneq ("$(wildcard $(DEPS))", "")
include $(DEPS)
endif

$(LIB): $(LINK_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(LINK_OBJ_DIR)/%.o: $(SRC_DIR)/%.c Makefile $(PC_FILE)
	$(CC) $(CFLAGS) -o $@ -c $(filter %.c, $^)

$(DEP_DIR)/%.d: $(SRC_DIR)/%.c
	@echo -n $(LINK_OBJ_DIR)/ > $@
	$(CC) $(CFLAGS) -MM $^ >> $@

PHONY += clean
clean:
	rm -rf $(shell find -name "*.o") $(LIB)

PHONY += distclean
distclean:
	rm -rf $(shell find -name "*.o") $(LIB)
	rm -rf $(BUILD_DIR)

.PHONY: $(PHONY)
