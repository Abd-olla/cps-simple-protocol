#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <openssl/hmac.h>
#include "microvisor.h"

#define NONCE_SIZE 32  // Size of nonce (random challenge) in bytes
#define OUTPUT_SIZE 32 // HMAC-SHA256 output size in bytes
#define KEY_SIZE 32    // Cryptographic key size in bytes
#define COUNTER_SIZE 4 // Counter size (32-bit integer)

// Monotonic counter for the Verifier, stored securely
__attribute__((section(".secure_data"))) volatile uint32_t C_V = 0;

/**
 * Opens a simulated UART connection for communication with the Prover.
 * Uses pseudo-terminals (pts) to simulate real hardware UART.
 *
 * @param device Path to the UART device (e.g., /dev/pts/X)
 * @return File descriptor for the opened UART connection, or -1 on failure
 */
int open_uart(const char *device) {
    int fd = open(device, O_RDWR | O_NOCTTY | O_NDELAY); // Open UART in read-write mode
    if (fd == -1) {
        perror("[VERIFIER] Failed to open UART");
        return -1;
    }

    struct termios options;
    tcgetattr(fd, &options);
    cfsetispeed(&options, B115200); // Set baud rate
    cfsetospeed(&options, B115200);
    options.c_cflag = CS8 | CLOCAL | CREAD; // 8-bit data, enable receiver
    tcsetattr(fd, TCSANOW, &options); // Apply settings

    tcflush(fd, TCIOFLUSH); // Clear any pending data
    return fd;
}

/**
 * Computes an HMAC for the attestation request using the authentication key (Kauth).
 * The HMAC is computed over { C_V, Valid Software State, Nonce }.
 *
 * @param nonce Pointer to the generated nonce
 * @param output Buffer to store the computed HMAC
 */
void compute_verifier_hmac(uint8_t *nonce, uint8_t *output) {
    uint8_t key[KEY_SIZE];
    uint8_t valid_state[KEY_SIZE];
    uint8_t hmac_input[COUNTER_SIZE + KEY_SIZE + NONCE_SIZE];

    get_secure_key(key, 0);  // Retrieve authentication key (Kauth)
    compute_valid_software_state(valid_state); // Compute valid software state (VS)

    // Construct HMAC input: { C_V || Valid Software State || Nonce }
    uint32_t temp_CV = C_V;
    memcpy(hmac_input, &temp_CV, COUNTER_SIZE);
    memcpy(hmac_input + COUNTER_SIZE, valid_state, KEY_SIZE);
    memcpy(hmac_input + COUNTER_SIZE + KEY_SIZE, nonce, NONCE_SIZE);

    unsigned int len = 0;
    HMAC(EVP_sha256(), key, KEY_SIZE, hmac_input, sizeof(hmac_input), output, &len);

    hex_dump("[VERIFIER] Computed HMAC", output, OUTPUT_SIZE);
}

/**
 * Reads a fixed number of bytes from UART safely.
 * Ensures all expected bytes are received before returning.
 *
 * @param fd UART file descriptor
 * @param buffer Pointer to the destination buffer
 * @param size Number of bytes to read
 */
void safe_uart_read(int fd, uint8_t *buffer, size_t size) {
    size_t received = 0;
    while (received < size) {
        ssize_t bytes_read = read(fd, buffer + received, size - received);
        if (bytes_read > 0) {
            received += bytes_read;
        }
    }
}

/**
 * Writes a fixed number of bytes to UART safely.
 * Ensures all bytes are transmitted before returning.
 *
 * @param fd UART file descriptor
 * @param buffer Pointer to the data to be sent
 * @param size Number of bytes to write
 */
void safe_uart_write(int fd, uint8_t *buffer, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        ssize_t bytes_written = write(fd, buffer + sent, size - sent);
        if (bytes_written > 0) {
            sent += bytes_written;
        }
    }
}

/**
 * Generates a random nonce for the attestation process.
 *
 * @param nonce Pointer to the buffer where the nonce will be stored
 */
void generate_nonce(uint8_t *nonce) {
    FILE *fp = fopen("/dev/urandom", "r");
    fread(nonce, 1, NONCE_SIZE, fp);
    fclose(fp);
}

int main() {
    initialize_keys(); // Load cryptographic keys at startup

    int uart_fd = open_uart("/dev/pts/7"); // Open simulated UART connection
    if (uart_fd == -1) return -1; // Exit if UART cannot be opened

    while (1) { // Continuous loop to send attestation requests
        uint8_t nonce[NONCE_SIZE];
        uint8_t hmac[OUTPUT_SIZE];
        uint8_t valid_state[KEY_SIZE];

        printf("[VERIFIER] Sending attestation request...\n");

        // Generate a fresh nonce for attestation request
        generate_nonce(nonce);
        hex_dump("[VERIFIER] Generated Nonce", nonce, NONCE_SIZE);

        // Increment counter (C_V = C_V + 1) to ensure freshness
        C_V++;

        // Compute HMAC for { C_V, Valid Software State, Nonce }
        compute_verifier_hmac(nonce, hmac);

        // Send attestation request: { C_V, Valid Software State, Nonce, HMAC }
        safe_uart_write(uart_fd, (uint8_t *)&C_V, COUNTER_SIZE);
        compute_valid_software_state(valid_state);
        safe_uart_write(uart_fd, valid_state, KEY_SIZE);
        safe_uart_write(uart_fd, nonce, NONCE_SIZE);
        safe_uart_write(uart_fd, hmac, OUTPUT_SIZE);

        printf("[VERIFIER] Request sent with counter: %u\n", C_V);

        // Read attestation report from Prover
        uint8_t report[1 + OUTPUT_SIZE];
        safe_uart_read(uart_fd, report, sizeof(report));

        // Verify attestation report
        if (report[0] == 1) {
            printf("[VERIFIER]  Attestation SUCCESSFUL!\n");
        } else {
            printf("[VERIFIER]  Attestation FAILED!\n");
        }

        sleep(5); // Wait before sending the next attestation request
    }

    close(uart_fd); // Close UART connection (never reached in infinite loop)
    return 0;
}

