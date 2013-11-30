

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>

#include <pthread.h>

#include <string.h>

#include "pole.h"
#include "rc4_cracker.h"
#include "md5.h"


inline uint8_t *prga(uint8_t *text, int tlen, state_t *key_state, uint8_t *e_text) {
    uint8_t i = key_state->i;
    uint8_t j = key_state->j;
    uint8_t *S = key_state->S;

    if (!e_text)
        return NULL;

    for (int k = 0; k < tlen; k++) {
        i = (i + 1); //% 256;
        j = (j + S[i]); //% 256;

        swap_bytes(S, i, j);

        e_text[k] = (S[(S[i] + S[j]) & 255 /*% 256*/]) ^ text[k];
    }

    key_state->i = i;
    key_state->j = j;

    return e_text;
}



inline void ksa(uint8_t *key, int keylen, state_t *key_state) {
    uint16_t i = 0;
    uint16_t j = 0;
    uint8_t *S = key_state->S;

    key_state->i = 0;
    key_state->j = 0;

    memcpy(S, S_init, 256);

    for (i = 0; i < 256; i++) {
        // We are assuming keylen is a power of two
        //  -- in the rc4_cracker.cpp file keylen is always 16
        j = (j + S[i] + key[i & (keylen - 1)/*% keylen*/]) & 255; //% 256;
        swap_bytes(S, i, j);
    }
}


ole_header_t get_header(POLE::Storage *storage) {
    char stream_name[] = "1Table";
    ole_header_t header = {0};

    POLE::Stream *stream = new POLE::Stream(storage, stream_name);
    if (!stream)
        return header;
    if (stream->fail())
        return header;

    // Read in the whole header at once
    int read = stream->read((unsigned char *) &header, sizeof(header));
    if (read != sizeof(header)) {
        std::cerr << "Error reading header!" << std::endl;
        memset(&header, 0, sizeof(header));
        return header;
    }
    
    delete stream;
    return header;
}


// Decrypt the document by reinitializing the
// RC4 encrpytion every 512 bytes.  For each
// 512 bytes block, increment the upper 4 
// bytes of the key
void decrypt_doc(POLE::Storage *storage, char *filename, uint64_t key_uint) {
    uint8_t buffer[512] = {0};
    uint8_t d_buffer[512] = {0};

    uint8_t key[9] = {0};
    state_t key_state;
    uint8_t pwdHash[16] = {0};

    memcpy(key, reinterpret_cast<uint8_t *>(&key_uint), 5);

    std::list<std::string> d_streams;
    d_streams.push_back("/1Table");
    d_streams.push_back("/WordDocument");
    std::list<std::string>::iterator it;
    for (it = d_streams.begin(); it != d_streams.end(); it++) {
        uint32_t key_upper = 0; /* handles bytes 6 to 9 */
        uint64_t read = 0;

        std::string name = *it;
        POLE::Stream *stream = new POLE::Stream(storage, name);
        if (!stream || stream->fail()) {
            std::cerr << "Failed to open stream " << name << std::endl;
            delete stream;
            break;
        }

        while ((read = stream->read(buffer, 512)) > 0) {
            // Add the upper 4 bytes of the key -- This is 
            // determined by "B" which is incremented for
            // every 512 bytes per stream.
            for (uint8_t ndx = 0; ndx < 4; ndx++) {
                key[5+ndx] = (key_upper >> (8*ndx)) & 0xff;
            }

            memset(pwdHash, 0, 16);
            md5((uint8_t *) key, 9, pwdHash);
            ksa((uint8_t *) pwdHash, 16, &key_state);
            prga((uint8_t *) buffer, read, &key_state, d_buffer);

            // Seek backwards and write the decrpyted data
            if ((key_upper == 0) && (name.compare("/WordDocument") == 0)) {
                // For the WordDocument stream, the first 68 bytes
                // are not obfuscated.  We need to flip the encrytion
                // bit though -- bit 1 in byte 12
                buffer[11] &= ~ENCRYPTION_BIT;
                buffer[11] &= ~READ_ONLY_BIT;
                memcpy(d_buffer, buffer, WORD_DOCUMENT_HEADER_SIZE);
            }

            stream->seek(stream->tell() - read);
            stream->write(d_buffer, read);

            key_upper++;
        }
        delete stream;

        // XXX Need to handle directories
        if(storage->isDirectory(name)) {
            std::cout << name << " is a directory" << std::endl;
            //visit(indent+1, storage, fullname + "/" );
        }
    }
}

void *crack_range(void *ptr) {
    thread_data_t *tdata = (thread_data_t *) ptr;
    uint64_t k                  = 0;
    uint8_t no_match            = 0;
    uint8_t key[9]              = {0};
    uint8_t key_hash[16]        = {0};
    uint8_t tmp_hash[16]        = {0};
    uint8_t d_verifier[16]      = {0};
    uint8_t d_verifier_hash[16] = {0};
    state_t key_state;

    // Allow the thread to be cancelled immediately
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    for (k = tdata->start_ndx; k < tdata->end_ndx; k++) {
        no_match = 0; // reset match flag

        // Convert to an array to use for the hash
        //memcpy(key, reinterpret_cast<uint8_t *>(&k), 5);
        uint8_t *tmp_array = reinterpret_cast<uint8_t *>(&k);
        key[0] = tmp_array[0];
        key[1] = tmp_array[1];
        key[2] = tmp_array[2];
        key[3] = tmp_array[3];
        key[4] = tmp_array[4];

        // Calculate the key state
        md5((uint8_t *) key, 9, key_hash);
        ksa(key_hash, 16, &key_state);

        // Decrypt the header verifier and hash
        prga(tdata->header.e_verifier,      16, &key_state, d_verifier);
        prga(tdata->header.e_verifier_hash, 16, &key_state, d_verifier_hash);
        md5((uint8_t *) d_verifier, 16, tmp_hash);

        // Compare the decrpyted hash with the hashed decrpyted verifier
        for (uint8_t b = 0; b < 16; b++) {
            if (d_verifier_hash[b] != tmp_hash[b]) {
                no_match = 1;
                break;
            }
        }

        // Stop we a match is found
        if (!no_match)
            break;
    }

    if ((k != tdata->end_ndx) && (no_match == 0)) {
        tdata->ret_val = k;

        std::cout << "Found a match: ";
        for (uint8_t b = 0; b < 5; b++) {
            key[b] = (k >> (8*b)) & 0xff;
            printf("%02x ", key[b]);
        }
        printf("(%lu)\n", k);
    } else {
        return (void *) 1;
    }

    return (void *) 0;
}


int main(int argc, char *argv[]) {
    pthread_t thread_id[NUM_THREADS] = {0};
    thread_data_t *tdata = NULL;

    if (argc < 2) {
        std::cout << "Usage:" << std::endl;
        std::cout << argv[0] << " filename" << std::endl;
        return 0;
    }

    char *filename = argv[1];

    POLE::Storage *storage = new POLE::Storage(filename);
    storage->open(true, false);
    if (storage->result() != POLE::Storage::Ok) {
        std::cerr << "Error on file " << filename << std::endl;
        return 1;
    }

    // Test document key: CC D7 F8 F6 95
    //decrypt_doc(storage, filename, 0x95f6f8d7cc);
    //return 0;

    ole_header_t header = get_header(storage);

    tdata = (thread_data_t *) calloc(NUM_THREADS, sizeof(thread_data_t));
    if (!tdata) {
        std::cerr << "Failed to calloc the thread data!" << std::endl;
        return 1;
    }

    for (uint64_t i = 0; i < NUM_THREADS; i++) {
        memcpy(&(tdata[i].header), &header, sizeof(header));
        tdata[i].start_ndx = SEARCH_BASE + ((FORTY_BIT_MAX - SEARCH_BASE) / NUM_THREADS) * i;
        tdata[i].end_ndx = tdata[i].start_ndx + ((FORTY_BIT_MAX - SEARCH_BASE) / NUM_THREADS);
        tdata[i].ret_val = 0;

        pthread_create(&thread_id[i], NULL, crack_range, (void *) &tdata[i]);
    }

    int i = 0;
    int tfinished = 0;
    while (tfinished < NUM_THREADS) {
        struct timespec ts = {1, 0};
        int retval[1] = {0};

        if (thread_id[i] == NUM_THREADS) {
            // already joined
            i++;
            if (i >= NUM_THREADS)
                i = 0;

            continue;
        }

        if (0 == pthread_timedjoin_np(thread_id[i], (void **) &retval, &ts)) {
            // Successful

            if (retval[0] == 0) {
                fprintf(stderr, "Thread found solution...");

                // kill the rest of the threads
                for (int j = 0; j < NUM_THREADS; j++) {
                    if ((j == i) || (thread_id[j] == NUM_THREADS)) 
                        continue;

                    pthread_cancel(thread_id[j]);
                    pthread_join(thread_id[j], NULL);
                    thread_id[j] = NUM_THREADS;
                }
                break;
            }
            else 
            {
                thread_id[i] = NUM_THREADS;
                tfinished++;
            }
        }
        // timed-out

        i++;
        if (i >= NUM_THREADS)
            i = 0;
    }

    if (thread_id[i] == NUM_THREADS) {
        std::cerr << "Invalid thread id: " << i << std::endl;
        return 1;
    }

    fprintf(stderr, "Decrypting doc now");
    decrypt_doc(storage, filename, tdata[i].ret_val);
    free(tdata);

    delete storage;
    return 0;
}
