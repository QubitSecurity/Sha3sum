# Sha3sum 

SHA-3 was known as Keccak and is a hash function designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche.
<br>In October 2012, Keccak won the NIST hash function competition, and is proposed as the SHA-3 standard.
<br>The SHAKE method is useful as it can be used to create a hash method of a variable length. For example the 128-bit version will produce a hash value is 32 hex characters.

## Implemeation

SHA3-Keccak 224, 256, 384, 512
<br>SHA3-SHAKE 128, 256

## Make

```
LDFLAGS=-flto -fPIC
CC=gcc
RM=/bin/rm -f

SRC = sha3sum.c keccak_hash.c
TARGET = sha3sum
all:
	$(CC) $(LDFLAGS) -Os -o $(TARGET) $(SRC)

```

## Usage

```
# sha3sum --sha3 bits [e.g. 224, 256, 384, 512] file [file2]...
# sha3sum --shake bits [e.g. 128 or 256] file [file2]...
```