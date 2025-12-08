#include <stdio.h>
#include <stdint.h>
#include <string.h>

// =============================================================
// PART 1: AES-128 Implementation (Symmetric)
// Signature: S-Box Lookups, ShiftRows, MixColumns logic
// =============================================================

// Standard AES S-Box (High detection confidence)
static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  // ... (Full S-box is implied for brevity in source, but pattern is enough)
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
};

void aes_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]]; // The Classic AES Signature
    }
}

void aes_shift_rows(uint8_t *state) {
    uint8_t temp;
    // Row 1 shift 1
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    // Row 2 shift 2
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
}

void aes_encrypt_block(uint8_t *data, uint8_t *key) {
    // Simple mock of rounds to generate CFG structure
    for(int round=0; round<10; round++) {
        aes_sub_bytes(data);
        aes_shift_rows(data);
        // AddRoundKey mock
        for(int i=0; i<16; i++) data[i] ^= key[i]; 
    }
}

// =============================================================
// PART 2: ECC Implementation (Asymmetric)
// Signature: Point Addition, Scalar Mult, Modular Arithmetic
// =============================================================

// Define a simplified Finite Field for structural demonstration
#define P 97 

typedef struct {
    int x;
    int y;
} Point;

// Modular Inverse (Extended Euclidean Algo pattern)
int modInverse(int n) {
    for (int x = 1; x < P; x++)
        if (((n % P) * (x % P)) % P == 1)
            return x;
    return 1;
}

// Elliptic Curve Point Addition
// Formula: s = (y2 - y1) / (x2 - x1) mod p
Point ecc_point_add(Point p, Point q) {
    Point r;
    if (p.x == 0 && p.y == 0) return q;
    if (q.x == 0 && q.y == 0) return p;

    int num = (q.y - p.y);
    int den = (q.x - p.x);
    
    // Handle negatives
    while(num < 0) num += P;
    while(den < 0) den += P;

    int s = (num * modInverse(den)) % P;
    
    r.x = (s*s - p.x - q.x) % P;
    while(r.x < 0) r.x += P;
    
    r.y = (s*(p.x - r.x) - p.y) % P;
    while(r.y < 0) r.y += P;
    
    return r;
}

// Elliptic Curve Point Doubling
// Formula: s = (3*x1^2 + a) / (2*y1) mod p
Point ecc_point_double(Point p) {
    Point r;
    int a = 2; // Curve parameter 'a'
    
    int num = (3 * p.x * p.x + a) % P;
    int den = (2 * p.y) % P;
    
    int s = (num * modInverse(den)) % P;
    
    r.x = (s*s - 2*p.x) % P;
    while(r.x < 0) r.x += P;
    
    r.y = (s*(p.x - r.x) - p.y) % P;
    while(r.y < 0) r.y += P;
    
    return r;
}

// Scalar Multiplication (Double-and-Add Algorithm)
// This is the #1 signature for ECC / RSA / Diffie-Hellman
Point ecc_scalar_mult(Point p, int k) {
    Point r = {0, 0}; // Identity element
    Point temp = p;
    
    // Loop over bits of the scalar 'k'
    while (k > 0) {
        // If bit is set, add
        if (k & 1) {
            if (r.x == 0 && r.y == 0) r = temp;
            else r = ecc_point_add(r, temp);
        }
        
        // Double the point
        temp = ecc_point_double(temp);
        
        // Shift scalar
        k >>= 1;
    }
    return r;
}

// =============================================================
// MAIN ENTRY
// =============================================================
int main() {
    printf("[*] Starting Hybrid Crypto Testbench...\n");

    // --- Execute AES ---
    uint8_t aes_data[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0};
    uint8_t aes_key[16]  = {0x12, 0x34, 0x56, 0x78, 0};
    
    printf("[.] Running AES Encryption...\n");
    aes_encrypt_block(aes_data, aes_key);
    printf("    AES Output: %02X %02X ...\n", aes_data[0], aes_data[1]);

    // --- Execute ECC ---
    printf("[.] Running ECC Scalar Multiplication...\n");
    Point G = {15, 6}; // Generator point
    int private_key = 7;
    
    Point pub = ecc_scalar_mult(G, private_key);
    printf("    ECC Public Key: (%d, %d)\n", pub.x, pub.y);

    return 0;
}
