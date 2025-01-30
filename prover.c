#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <openssl/hmac.h>
#include "microvisor.h"

#define NONCE_SIZE 32  // Size of nonce (random challenge) in bytes
#define OUTPUT_SIZE 32 // HMAC-SHA256 output size in bytes
#define KEY_SIZE 32    // Cryptographic key size in bytes
#define COUNTER_SIZE 4 // Counter size (32-bit integer)

// Monotonic counter for the Prover, stored securely
__attribute__((section(".secure_data"))) volatile uint32_t C_P = 0;

/**
 * Opens a simulated UART connection for communication with the Verifier.
 * Uses pseudo-terminals (pts) to simulate real hardware UART.
 *
 * @param device Path to the UART device (e.g., /dev/pts/X)
 * @return File descriptor for the opened UART connection, or -1 on failure
 */
int open_uart(const char *device) {
    int fd = open(device, O_RDWR | O_NOCTTY | O_NDELAY); // Open UART in read-write mode
    if (fd == -1) {
        perror("[PROVER] Failed to open UART");
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
 * Computes an HMAC for the Prover using the received attestation request.
 * The HMAC is computed over { C_V, Valid Software State, Nonce } using Kauth.
 *
 * @param C_V Counter value received from the Verifier
 * @param nonce Pointer to the received nonce
 * @param output Buffer to store the computed HMAC
 */
void compute_prover_hmac(uint32_t C_V, uint8_t *nonce, uint8_t *output) {
    uint8_t key[KEY_SIZE];
    uint8_t valid_state[KEY_SIZE];
    uint8_t hmac_input[COUNTER_SIZE + KEY_SIZE + NONCE_SIZE];

    get_secure_key(key, 0);  // Retrieve authentication key (Kauth)
    compute_valid_software_state(valid_state); // Compute valid software state (VS)

    // Construct HMAC input: { C_V || Valid Software State || Nonce }
    memcpy(hmac_input, &C_V, COUNTER_SIZE);
    memcpy(hmac_input + COUNTER_SIZE, valid_state, KEY_SIZE);
    memcpy(hmac_input + COUNTER_SIZE + KEY_SIZE, nonce, NONCE_SIZE);

    unsigned int len = 0;
    HMAC(EVP_sha256(), key, KEY_SIZE, hmac_input, sizeof(hmac_input), output, &len);

    hex_dump("[PROVER] Computed HMAC", output, OUTPUT_SIZE);
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

int main() {
    initialize_keys(); // Load cryptographic keys at startup

    int uart_fd = open_uart("/dev/pts/8"); // Open simulated UART connection
    if (uart_fd == -1) return -1; // Exit if UART cannot be opened

    while (1) { // Continuous loop to handle multiple attestation requests
        uint32_t C_V;
        uint8_t valid_state[KEY_SIZE], nonce[NONCE_SIZE], received_hmac[OUTPUT_SIZE];

        printf("[PROVER] Waiting for attestation request...\n");

        // Read attestation request: { C_V, Valid Software State, Nonce, HMAC }
        safe_uart_read(uart_fd, (uint8_t *)&C_V, COUNTER_SIZE);
        safe_uart_read(uart_fd, valid_state, KEY_SIZE);
        safe_uart_read(uart_fd, nonce, NONCE_SIZE);
        safe_uart_read(uart_fd, received_hmac, OUTPUT_SIZE);

        printf("[PROVER] Received C_V: %u\n", C_V);

        // Check counter freshness: Reject if C_P >= C_V (prevents replay attacks)
        if (C_P >= C_V) {
            printf("[PROVER]  C_P >= C_V, rejecting attestation request\n");
            uint8_t report[1 + OUTPUT_SIZE] = {0}; // Report failure (0 flag)
            safe_uart_write(uart_fd, report, sizeof(report));
            continue; // Skip processing this request
        }

        // Compute expected HMAC using received parameters
        uint8_t expected_hmac[OUTPUT_SIZE];
        compute_prover_hmac(C_V, nonce, expected_hmac);

        // Verify received HMAC against the expected value
        if (memcmp(received_hmac, expected_hmac, OUTPUT_SIZE) == 0) {
            // Update prover counter to match verifier counter
            C_P = C_V;

            // Prepare successful attestation report
            uint8_t report[1 + OUTPUT_SIZE] = {1}; // Success flag (1)
            compute_prover_hmac(C_P, nonce, report + 1); // Compute final HMAC
            safe_uart_write(uart_fd, report, sizeof(report)); // Send report

            printf("[PROVER]  Attestation SUCCESS!\n");
        } else {
            printf("[PROVER]  Attestation FAILED!\n");
        }
    }

    close(uart_fd); // Close UART connection (never reached in infinite loop)
    return 0;
}

