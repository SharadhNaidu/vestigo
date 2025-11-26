#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) ( \
    a += b,  d ^= a,  d = ROTL(d,16), \
    c += d,  b ^= c,  b = ROTL(b,12), \
    a += b,  d ^= a,  d = ROTL(d, 8), \
    c += d,  b ^= c,  b = ROTL(b, 7))

void chacha20_block(uint32_t out[16], uint32_t const in[16])
{
    int i;
    uint32_t x[16];

    for (i = 0; i < 16; ++i)
        x[i] = in[i];

    // 10 loops × 2 rounds/loop = 20 rounds
    for (i = 0; i < 10; i++) {
        // Odd round
        QR(x[0], x[4], x[ 8], x[12]); // column 0
        QR(x[1], x[5], x[ 9], x[13]); // column 1
        QR(x[2], x[6], x[10], x[14]); // column 2
        QR(x[3], x[7], x[11], x[15]); // column 3
        // Even round
        QR(x[0], x[5], x[10], x[15]); // diagonal 1 (main diagonal)
        QR(x[1], x[6], x[11], x[12]); // diagonal 2
        QR(x[2], x[7], x[ 8], x[13]); // diagonal 3
        QR(x[3], x[4], x[ 9], x[14]); // diagonal 4
    }

    for (i = 0; i < 16; ++i)
        out[i] = x[i] + in[i];
}

void chacha20_encrypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    uint32_t state[16];
    uint32_t block[16];
    uint8_t block8[64];
    size_t i, j;

    const char *constants = "expand 32-byte k";
    
    // Setup state
    state[0] = ((uint32_t*)constants)[0];
    state[1] = ((uint32_t*)constants)[1];
    state[2] = ((uint32_t*)constants)[2];
    state[3] = ((uint32_t*)constants)[3];
    
    for(i=0; i<8; i++) state[4+i] = ((uint32_t*)key)[i];
    
    state[12] = counter;
    for(i=0; i<3; i++) state[13+i] = ((uint32_t*)nonce)[i];

    while (len > 0) {
        chacha20_block(block, state);
        state[12]++; // Increment counter

        // Serialize block to bytes (Little Endian)
        for (i = 0; i < 16; i++) {
            uint32_t v = block[i];
            block8[i*4+0] = (uint8_t)(v >> 0);
            block8[i*4+1] = (uint8_t)(v >> 8);
            block8[i*4+2] = (uint8_t)(v >> 16);
            block8[i*4+3] = (uint8_t)(v >> 24);
        }
        
        size_t chunk = (len < 64) ? len : 64;
        for (j = 0; j < chunk; j++) {
            out[j] = in[j] ^ block8[j];
        }
        
        len -= chunk;
        in += chunk;
        out += chunk;
    }
}

int main() {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t data[64] = "Hello ChaCha20!";
    uint8_t ciphertext[64];
    
    chacha20_encrypt(ciphertext, data, 64, key, nonce, 1);
    
    printf("ChaCha20 Test: %02x %02x\n", ciphertext[0], ciphertext[1]);
    return 0;
}
