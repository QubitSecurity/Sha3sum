LDFLAGS=-flto -fPIC
CC=gcc
RM=/bin/rm -f

SRC = sha3sum.c keccak_hash.c
TARGET = sha3sum
all:
	$(CC) $(LDFLAGS) -Os -o $(TARGET) $(SRC)


