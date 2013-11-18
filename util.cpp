

#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include <stdint.h>
#include <string.h>

#include "util.h"

#define swap_bytes(data, i, j) {\
    int tmp = (data)[(i)]; \
    (data)[(i)] = (data)[(j)]; \
    (data)[(j)] = tmp;     \
}

uint8_t *prga(uint8_t *text, int tlen, state_t *key_state, uint8_t *e_text) {
    uint8_t i = key_state->i;
    uint8_t j = key_state->j;
    uint8_t *S = key_state->S;

    for (int k = 0; k < tlen; k++) {
        uint8_t ks;

        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        swap_bytes(S, i, j);

        ks = S[(S[i] + S[j]) % 256];
        
        if (e_text)
            e_text[k] = ks ^ text[k];
        else
            printf("%02X ", ks ^ text[k]);
    }

    if (!e_text)
        std::cout << std::endl;

    key_state->i = i;
    key_state->j = j;

    return e_text;
}


void ksa(uint8_t *key, int keylen, state_t *key_state) {
    uint8_t i = 0;
    uint8_t j = 0;
    uint8_t *S = key_state->S;

    key_state->i = 0;
    key_state->j = 0;

    do {
        S[i] = i;
    } while (i++ != 255);

    i = 0;
    do {
        j = (j + S[i] + key[i % keylen]) % 256;
        swap_bytes(S, i, j);
    } while (i++ != 255);
}
