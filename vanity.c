#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ecdsa.h"
#include "rand.h"
#include "bignum.h"
#include "secp256k1.h"
#include "sha3.h"


void dumpBuffer(uint8_t *buffer, uint8_t length) {
    printf("0x");
    for (uint8_t i = 0; i < length; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

void showUsage() {
    printf("Usage:\n");
    printf("    vanity-contract PATTERN\n");
}

int main(int argc, char **argv) {
    setlinebuf(stdout);

    if (argc != 2) {
        showUsage();
        return 1;
    }

    uint32_t patternLength = strlen(argv[1]);
    if (patternLength > 40) {
        showUsage();
        printf("Error: PATTERN must be 40 characters or less\n");
        return 1;
    }

    uint8_t pattern[40];
    for (uint8_t i = 0; i < patternLength; i++) {
        uint8_t c = argv[1][i];
        if (c >= 0x30 && c <= 0x39) {
            pattern[i] = c - 0x30;
        } else if (c >=0x41 && c <= 0x46) {
            pattern[i] = c - 0x41 + 10;
        } else if (c >=0x61 && c <= 0x66) {
            pattern[i] = c - 0x61 + 10;
        } else {
            showUsage();
            printf("Error: Invalid character at position %d: \"%c\"\n", i, c);
            return 1;
        }
    }

    time_t lastTime = time(NULL);

    // Start with any random private key
    uint8_t privateKey[32];
    random_buffer(privateKey, 32);
    //dumpBuffer(privateKey, 32);

    // The RLP encoded data (will go here)
    uint8_t rlp[2 + 20 + 1];

    // Length of all children items with their prefixes; 22 bytes
    //  - 1 byte address length
    //  - 20 bytes address
    //  - 1 byte zero nonce
    rlp[0] = 0xc0 + 22;

    // Length of item[0] (i.e. the address); 20 bytes
    rlp[1] = 0x80 + 20;

    // rlp[2:2 + 20] = current address to test

    // Length of the item[1] (i.e. the nonce); 0 bytes (for striped nonce 0)
    rlp[2 + 20] = 0x80 + 0;

    // Used to compute the public key
    curve_point publicPoint;
    bignum256 secretExponent;
    uint8_t publicKey[64];

    // Used to compute the public key and the contract address
    SHA3_CTX context;
    uint8_t hash[32];


    uint32_t count = 0;
    while (1) {

        // Compute the public key (k * curve.G)
        bn_read_be(privateKey, &secretExponent);
        scalar_multiply(&secp256k1, &secretExponent, &publicPoint);
        bn_write_be(&publicPoint.x, &publicKey[0]);
        bn_write_be(&publicPoint.y, &publicKey[32]);

        // Compute the wallet address
        keccak_256_Init(&context);
        keccak_Update(&context, publicKey, 64);
        keccak_Final(&context, hash);

        // Place the address into the RLP data
        memcpy(&rlp[2], &hash[12], 20);

        // Compute the contract address from the RLP data
        keccak_256_Init(&context);
        keccak_Update(&context, rlp, sizeof(rlp));
        keccak_Final(&context, hash);

        // Check for a match, nibble-by-nibble...
        uint8_t found = 1;
        for (uint8_t i = 0; i < patternLength; i++) {
            uint8_t nibble = hash[12 + i / 2];
            if (i % 2 == 0) {
                nibble >>= 4;
            } else {
                nibble &= 0x0f;
            }

            // ...not a match
            if (nibble != pattern[i]) {
                found = 0;
                break;
            }
        }

        // Found a match; show it!
        if (found) {
            printf("Private Key: ");
            dumpBuffer(privateKey, 32);
            printf("EOA Address: ");
            dumpBuffer(&rlp[2], 20);
            printf("Contract Address: ");
            dumpBuffer(&hash[12], 20);
            printf("\n");
        }

        // A little bit of an update so we know what's happening
        count++;
        if (count % 100000 == 0) {
            time_t now = time(NULL);
            float dt = now - lastTime;
            lastTime = now;
            //printf("Tried=%d Speed=%f a/s\n", count, 100000.0 / dt);
        }

        // Increment the private key
        for (uint8_t i = 31; i > 0; i--) {
           privateKey[i]++;
           if (privateKey[i] != 0) { break; }
        }
    }
}
