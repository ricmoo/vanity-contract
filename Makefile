default: vanity
all: vanity

vanity.o: bignum.c ecdsa.c rand.c secp256k1.c sha3.c vanity.c

vanity: bignum.o ecdsa.o rand.o secp256k1.o sha3.o vanity.o
  
