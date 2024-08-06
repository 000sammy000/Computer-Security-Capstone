# Makefile

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Target executable name
TARGET = random

# Source files
SRC = random.c
SH = doll.sh

# Default target
all: $(TARGET)

# Rule to compile the target
$(TARGET): $(SRC) $(SH)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	chmod +x $(TARGET)
	chmod +x $(SH)

# Clean up build files
clean:
	rm -f $(TARGET)
