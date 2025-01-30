#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "microvisor.h"
#include <openssl/hmac.h>

#define KEY_SIZE 32  // Size of cryptographic keys in bytes
#define OUTPUT_SIZE 32  // HMAC-SHA256 output size in bytes
#define SOFTWARE_CODE "ExampleFirmwareV1"  // Dummy software representation

// Securely store keys in `.secure_data` section to prevent unauthorized access
__attribute__((section(".secure_data"))) volatile uint8_t Kauth[KEY_SIZE];   // Authentication key
__attribute__((section(".secure_data"))) volatile uint8_t Kattest[KEY_SIZE]; // Attestation key

/**
 * Load a cryptographic key from a file.
 * This function reads a 32-byte key from a specified binary file into memory.
 *
 * @param key Pointer to the buffer where the key will be stored.
 * @param filename Path to the key file.
 */
void load_key_from_file(uint8_t *key, const char *filename) {
    FILE *fp = fopen(filename, "rb"); // Open the key file in binary mode
    if (fp) {
        fread(key, 1, KEY_SIZE, fp);  // Read the key into the provided buffer
        fclose(fp);
    } else {
        perror("Error loading key");  // Print error message if file cannot be opened
    }
}

/**
 * Retrieve a securely stored key (either Kauth or Kattest).
 * The function copies the selected key into the provided output buffer.
 *
 * @param key_out Pointer to the buffer where the key will be copied.
 * @param key_type 0 for Kauth (authentication), 1 for Kattest (attestation).
 */
void get_secure_key(uint8_t *key_out, uint8_t key_type) {
    if (key_type == 0) {
        memcpy(key_out, (const uint8_t *)Kauth, KEY_SIZE);  // Retrieve authentication key
        hex_dump("[MICROVISOR] Kauth Retrieved", key_out, KEY_SIZE);
    } else if (key_type == 1) {
        memcpy(key_out, (const uint8_t *)Kattest, KEY_SIZE);  // Retrieve attestation key
        hex_dump("[MICROVISOR] Kattest Retrieved", key_out, KEY_SIZE);
    }
}

/**
 * Compute a valid software state hash using the attestation key.
 * This simulates integrity verification by hashing a predefined software code.
 *
 * @param state Buffer where the computed valid state hash will be stored.
 */
void compute_valid_software_state(uint8_t *state) {
    uint8_t key[KEY_SIZE];  // Buffer to store the attestation key
    get_secure_key(key, 1);  // Retrieve Kattest

    // Compute HMAC(Kattest, SOFTWARE_CODE)
    unsigned int len = 0;
    HMAC(EVP_sha256(), key, KEY_SIZE, (uint8_t*)SOFTWARE_CODE, strlen(SOFTWARE_CODE), state, &len);

    hex_dump("[MICROVISOR] Computed Valid Software State (VS)", state, OUTPUT_SIZE);
}

/**
 * Initialize cryptographic keys at system startup.
 * Loads Kauth and Kattest from external files into secure memory.
 */
void initialize_keys() {
    load_key_from_file((uint8_t *)Kauth, "kauth.key");   // Load authentication key from file
    load_key_from_file((uint8_t *)Kattest, "kattest.key"); // Load attestation key from file

    // Log the loaded keys for debugging purposes
    hex_dump("[MICROVISOR] Loaded Kauth", (uint8_t *)Kauth, KEY_SIZE);
    hex_dump("[MICROVISOR] Loaded Kattest", (uint8_t *)Kattest, KEY_SIZE);
}

/**
 * Print a hex dump of a given data buffer.
 * This is useful for debugging cryptographic operations.
 *
 * @param label Description of the data being printed.
 * @param data Pointer to the buffer to be printed.
 * @param len Length of the data buffer.
 */
void hex_dump(const char *label, uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);  // Print each byte as a two-digit hexadecimal number
    }
    printf("\n");
}

