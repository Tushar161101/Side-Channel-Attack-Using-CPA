#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Byte structure: two 4-bit nibbles
typedef struct __attribute__((__packed__)) byte {
    uint8_t nibble1 : 4;
    uint8_t nibble2 : 4;
} byte;

// SBox and inverse SBox
uint8_t S[] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
uint8_t invS[] = {0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

uint8_t P[] = {
    0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

uint64_t fromBytesToLong(const uint8_t *bytes) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

void fromLongToBytes(uint64_t block, uint8_t *bytes) {
    for (int i = 0; i < 8; i++) {
        bytes[7 - i] = block & 0xFF;
        block >>= 8;
    }
}

uint64_t permute(uint64_t source) {
    uint64_t permutation = 0;
    for (int i = 0; i < 64; i++) {
        permutation |= ((source >> (63 - i)) & 0x1) << (63 - P[i]);
    }
    return permutation;
}

uint64_t inversepermute(uint64_t source) {
    uint64_t permutation = 0;
    for (int i = 0; i < 64; i++) {
        permutation |= ((source >> (63 - P[i])) & 0x1) << (63 - i);
    }
    return permutation;
}

uint8_t Sbox(uint8_t input) { return S[input]; }
uint8_t inverseSbox(uint8_t input) { return invS[input]; }

uint16_t getKeyLow(const uint8_t *keyBytes) {
    // Get the lower 4 bytes from a 10-byte (80-bit) key
    return (keyBytes[8] << 8) | keyBytes[9];
}

// Generate 32 subkeys from 80-bit key
void generateSubkeys(const uint8_t *keyBytes, uint64_t *subKeys) {
    uint64_t keyHigh = 0;
    for (int i = 0; i < 8; i++) {
        keyHigh = (keyHigh << 8) | keyBytes[i];
    }
    uint16_t keyLow = getKeyLow(keyBytes);

    subKeys[0] = keyHigh;

    for (int i = 1; i < 32; i++) {
        uint64_t temp1 = keyHigh;
        uint16_t temp2 = keyLow;

        // Left rotate 61 bits
        keyHigh = (keyHigh << 61) | ((uint64_t)temp2 << 45) | (temp1 >> 19);
        keyLow = (temp1 >> 3) & 0xFFFF;

        // Apply SBox to high nibble
        uint8_t temp = Sbox(keyHigh >> 60);
        keyHigh = (keyHigh & 0x0FFFFFFFFFFFFFFFLL) | ((uint64_t)temp << 60);

        // XOR round counter
        keyLow ^= ((i & 0x01) << 15);
        keyHigh ^= (i >> 1);

        subKeys[i] = keyHigh;
    }
}

// Encrypts 64-bit block in-place
void present_encrypt(uint8_t *block, const uint8_t *keyBytes) {
    uint64_t subkeys[32];
    generateSubkeys(keyBytes, subkeys);

    uint64_t state = fromBytesToLong(block);
    byte stateBytes[8];

    for (int i = 0; i < 31; i++) {
        state ^= subkeys[i];
        // Convert to bytes for S-box
        for (int j = 0; j < 8; j++) {
            uint8_t b = (state >> (56 - j * 8)) & 0xFF;
            stateBytes[j].nibble1 = Sbox((b >> 4) & 0xF);
            stateBytes[j].nibble2 = Sbox(b & 0xF);
        }
        // Convert back to state
        state = 0;
        for (int j = 0; j < 8; j++) {
            state = (state << 4) | (stateBytes[j].nibble1 & 0xF);
            state = (state << 4) | (stateBytes[j].nibble2 & 0xF);
        }
        state = permute(state);
    }

    state ^= subkeys[31];
    fromLongToBytes(state, block);
}

// Decrypts 64-bit block in-place
void present_decrypt(uint8_t *block, const uint8_t *keyBytes) {
    uint64_t subkeys[32];
    generateSubkeys(keyBytes, subkeys);

    uint64_t state = fromBytesToLong(block);
    byte stateBytes[8];

    for (int i = 0; i < 31; i++) {
        state ^= subkeys[31 - i];
        state = inversepermute(state);

        for (int j = 0; j < 8; j++) {
            uint8_t b = (state >> (56 - j * 8)) & 0xFF;
            stateBytes[j].nibble1 = inverseSbox((b >> 4) & 0xF);
            stateBytes[j].nibble2 = inverseSbox(b & 0xF);
        }
        state = 0;
        for (int j = 0; j < 8; j++) {
            state = (state << 4) | (stateBytes[j].nibble1 & 0xF);
            state = (state << 4) | (stateBytes[j].nibble2 & 0xF);
        }
    }

    state ^= subkeys[0];
    fromLongToBytes(state, block);
}
