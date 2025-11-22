#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint8_t state[16];


void process_block(uint8_t* input) {
    printf("[LOG] Processing block: ");
    for(int i=0; i<16; i++) {
        
        state[i] = input[i] ^ 0xFF; 
        printf("%02x ", state[i]);
    }
    printf("\n");
}

int main() {
    // Simulating a 16-byte packet
    uint8_t data[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    printf("--- System Start (Baseline) ---\n");
    
    for(int i=0; i<4; i++) {
        process_block(data);
    }

    printf("--- System Shutdown ---\n");
    return 0;
}