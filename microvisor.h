#ifndef MICROVISOR_H
#define MICROVISOR_H

#include <stdint.h>
#include <stddef.h>

// Function prototypes
void get_secure_key(uint8_t *key_out, uint8_t key_type);
void compute_valid_software_state(uint8_t *state);
void hex_dump(const char *label, uint8_t *data, size_t len);
void initialize_keys();

#endif // MICROVISOR_H

