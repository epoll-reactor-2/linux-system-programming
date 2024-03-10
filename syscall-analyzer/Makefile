CC=gcc
BIN=syscall_analyzer

all: ana

SRC=$(shell find . -name '*.c')

$(info SRC $(OBJ))

ana:
	$(CC) $(SRC) -o $(BIN)

.PHONY: clean
clean:
	@rm -rf $(BIN)