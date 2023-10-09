#include <stdio.h>
#include <stdint.h>

#define CANARY_SIZE 4  // Size of the canary in bytes (64 bits)

// Define the CLZ function (as provided)
uint16_t count_leading_zeros(uint64_t x)
{
    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    x |= (x >> 32);

    /* count ones (population count) */
    x -= ((x >> 1) & 0x5555555555555555);
    x = ((x >> 2) & 0x3333333333333333) + (x & 0x3333333333333333);
    x = ((x >> 4) + x) & 0x0f0f0f0f0f0f0f0f;
    x += (x >> 8);
    x += (x >> 16);

    return (64 - (x & 0x7f));
}

// Function to simulate a buffer overflow attack
void buffer_overflow_attack(char* buffer)
{
    // Overwrite the return address with a malicious address
    uint64_t malicious_address = 0xDEADBEEF;
    *((uint64_t*)(buffer + CANARY_SIZE)) = malicious_address;
}

int main()
{
    char buffer[32];  // Example buffer with space for the canary and data

    // Generate a random canary value (simulated)
    uint64_t canary_value = 0x123456789ABCDEF0;

    // Place the canary value at the beginning of the buffer
    *((uint64_t*)buffer) = canary_value;

    // Simulate a buffer overflow attack
    buffer_overflow_attack(buffer);

    // Check the integrity of the canary value using CLZ
    uint64_t stored_canary = *((uint64_t*)buffer);
    uint16_t clz_result = count_leading_zeros(stored_canary ^ canary_value);

    // If CLZ detects a change in the canary value, it indicates an attack
    if (clz_result != 64) {
        printf("Buffer overflow detected! The value start to be different at %d bits from left.\n", clz_result+1);
    } else {
        printf("No buffer overflow detected.\n");
    }

    return 0;
}
