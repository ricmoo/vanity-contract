W        = -Wall
OPT      = -O3 -g
CCFLAGS  = $(OPT) $(W) $(XCCFLAGS)

SRCS     = bignum.c ecdsa.c rand.c secp256k1.c sha3.c vanity.c


.PHONY: all clean

all: vanity

clean:
	rm -f *.o vanity


vanity: $(SRCS) Makefile
	$(CC) $(CCFLAGS) $(SRCS) -o vanity
