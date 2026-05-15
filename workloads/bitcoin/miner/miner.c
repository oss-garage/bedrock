// SPDX-License-Identifier: GPL-2.0
// Bedrock miner - registers feedback buffer and writes mined block hashes

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

// Feedback buffer layout:
// - Bytes 0-7: Number of blocks mined (u64, little-endian)
// - Bytes 8+: Block hashes (32 bytes each, newest first)

#define FEEDBACK_BUFFER_SIZE (64 * 1024)  // 64KB
#define BLOCK_HASH_SIZE 32
#define HEADER_SIZE 8  // u64 block count
#define MAX_HASHES ((FEEDBACK_BUFFER_SIZE - HEADER_SIZE) / BLOCK_HASH_SIZE)

// Hypercall numbers
#define HYPERCALL_REGISTER_FEEDBACK_BUFFER 2

static uint8_t *feedback_buffer = NULL;

// Register the feedback buffer with the hypervisor
static int register_feedback_buffer(void *buffer, size_t size, uint64_t index) {
    uint64_t result;
    __asm__ volatile(
        "mov $2, %%rax\n\t"          // HYPERCALL_REGISTER_FEEDBACK_BUFFER = 2
        "mov %1, %%rbx\n\t"          // RBX = buffer address
        "mov %2, %%rcx\n\t"          // RCX = size
        "mov %3, %%rdx\n\t"          // RDX = buffer index (0-15)
        "vmcall\n\t"
        "mov %%rax, %0\n\t"          // result = RAX
        : "=r"(result)
        : "r"((uint64_t)buffer), "r"((uint64_t)size), "r"(index)
        : "rax", "rbx", "rcx", "rdx"
    );
    return (result == 0) ? 0 : -1;
}

// Get the current block count from the feedback buffer
static uint64_t get_block_count(void) {
    uint64_t count;
    memcpy(&count, feedback_buffer, sizeof(count));
    return count;
}

// Set the block count in the feedback buffer
static void set_block_count(uint64_t count) {
    memcpy(feedback_buffer, &count, sizeof(count));
}

// Add a block hash to the feedback buffer
// Hash is stored as raw bytes (32 bytes, big-endian as returned by bitcoin-cli)
static void add_block_hash(const uint8_t *hash) {
    uint64_t count = get_block_count();

    if (count >= MAX_HASHES) {
        // Buffer full, shift hashes down (discard oldest)
        memmove(feedback_buffer + HEADER_SIZE + BLOCK_HASH_SIZE,
                feedback_buffer + HEADER_SIZE,
                (MAX_HASHES - 1) * BLOCK_HASH_SIZE);
        count = MAX_HASHES - 1;
    }

    // Add new hash at the current position
    size_t offset = HEADER_SIZE + count * BLOCK_HASH_SIZE;
    memcpy(feedback_buffer + offset, hash, BLOCK_HASH_SIZE);

    set_block_count(count + 1);
}

// Parse a hex string into bytes
static int parse_hex(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);

    // Skip leading/trailing whitespace
    while (*hex == ' ' || *hex == '\n' || *hex == '\r') hex++;
    hex_len = strlen(hex);
    while (hex_len > 0 && (hex[hex_len-1] == ' ' || hex[hex_len-1] == '\n' || hex[hex_len-1] == '\r')) {
        hex_len--;
    }

    if (hex_len != out_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }
    return 0;
}

// Generate a block and return the block hash
// Returns 0 on success, -1 on failure
static int generate_block(uint8_t *hash_out) {
    FILE *fp;
    char output[512];
    size_t total_read = 0;

    // Run bitcoin-cli generatetoaddress
    // The output is a JSON array with the block hash, e.g.:
    // [
    //   "0000000000000000000..."
    // ]
    fp = popen("bitcoin-cli -regtest -rpcuser=user -rpcpassword=password -rpcport=18443 "
               "generatetoaddress 1 2N9hLwkSqr1cPQAPxbrGVUjxyjD11G2e1he 2>&1", "r");
    if (fp == NULL) {
        perror("popen failed");
        return -1;
    }

    // Read all output (JSON may span multiple lines)
    while (total_read < sizeof(output) - 1) {
        size_t n = fread(output + total_read, 1, sizeof(output) - 1 - total_read, fp);
        if (n == 0) break;
        total_read += n;
    }
    output[total_read] = '\0';

    int status = pclose(fp);
    if (status != 0) {
        fprintf(stderr, "bitcoin-cli failed: %s", output);
        return -1;
    }

    // Parse JSON array: ["hash"] or [\n  "hash"\n]
    // Find the hash between quotes
    char *start = strchr(output, '"');
    if (!start) {
        fprintf(stderr, "Failed to parse block hash from output: %s", output);
        return -1;
    }
    start++;  // Skip opening quote

    char *end = strchr(start, '"');
    if (!end) {
        fprintf(stderr, "Failed to parse block hash from output: %s", output);
        return -1;
    }
    *end = '\0';

    // Parse the hex hash
    if (parse_hex(start, hash_out, BLOCK_HASH_SIZE) != 0) {
        fprintf(stderr, "Failed to parse hex hash: %s\n", start);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    int sleep_seconds = 600;  // Default: 10 minutes between blocks

    if (argc > 1) {
        sleep_seconds = atoi(argv[1]);
        if (sleep_seconds <= 0) {
            fprintf(stderr, "Invalid sleep interval: %s\n", argv[1]);
            return 1;
        }
    }

    printf("Bedrock miner starting (interval: %d seconds)\n", sleep_seconds);

    // Allocate page-aligned feedback buffer
    feedback_buffer = mmap(NULL, FEEDBACK_BUFFER_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS,
                           -1, 0);
    if (feedback_buffer == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // Initialize buffer
    memset(feedback_buffer, 0, FEEDBACK_BUFFER_SIZE);

    // Register with hypervisor (index 0 for the miner's single buffer)
    printf("Registering feedback buffer (%d bytes)...\n", FEEDBACK_BUFFER_SIZE);
    if (register_feedback_buffer(feedback_buffer, FEEDBACK_BUFFER_SIZE, 0) != 0) {
        fprintf(stderr, "Failed to register feedback buffer (not running in bedrock VM?)\n");
        // Continue anyway - we can still mine, just won't have feedback
    } else {
        printf("Feedback buffer registered successfully\n");
    }

    // Wait for bitcoind to start
    printf("Waiting for bitcoind to start...\n");
    sleep(10);

    // Mining loop
    while (1) {
        printf("Generating block...\n");

        uint8_t hash[BLOCK_HASH_SIZE];
        if (generate_block(hash) == 0) {
            add_block_hash(hash);

            // Print hash in hex
            printf("Block mined: ");
            for (int i = 0; i < BLOCK_HASH_SIZE; i++) {
                printf("%02x", hash[i]);
            }
            printf(" (total: %lu)\n", get_block_count());
        } else {
            printf("Block generation failed, will retry...\n");
        }

        printf("Sleeping %d seconds...\n", sleep_seconds);
        sleep(sleep_seconds);
    }

    return 0;
}
