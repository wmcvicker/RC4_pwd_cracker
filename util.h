

#include <stdint.h>

#define DEFAULT_TEXT_LEN 16

typedef struct state {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} state_t;


void ksa(uint8_t *key, int keylen, state_t *key_state);
uint8_t *prga(uint8_t *text, int tlen, state_t *key_state, uint8_t *e_text);
