SRC_DIR = src
BIN_DIR = bin
OBJ_DIR = obj

SRCS = $(wildcard $(SRC_DIR)/*.cpp)

OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS))

INC := -I$(SRC_DIR)

CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g
LDFLAGS =

ASM64	= yasm -f elf64 -DYASM -D__x86_64__

PROGS = sdb

.PHONY = all clean
all: $(PROGS)

$(shell mkdir -p $(OBJ_DIR))
$(shell mkdir -p $(BIN_DIR))

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) -c $(CFLAGS) $(INC) $< -o $@

$(PROGS): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) -lcapstone
clean:
	rm -f $(OBJ_DIR)/*.o $(PROGS)