//
// Created by almir on 3/27/17.
//

/* install: apt-get install libb64-dev */
#include <b64/cencode.h>
#include <b64/cdecode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* base64_encode(const char *input, u_int32_t max)
{
    /* set up a destination buffer large enough to hold the encoded data */
    char* output = (char*)malloc(max);
    /* keep track of our encoded position */
    char* c = output;
    /* store the number of bytes encoded by a single call */
    int cnt = 0;
    /* we need an encoder state */
    base64_encodestate s;

    /*---------- START ENCODING ----------*/
    /* initialise the encoder state */
    base64_init_encodestate(&s);
    /* gather data from the input and send it to the output */
    cnt = base64_encode_block(input, strlen(input), c, &s);
    c += cnt;
    /* since we have encoded the entire input string, we know that
       there is no more input data; finalise the encoding */
    cnt = base64_encode_blockend(c, &s);
    c += cnt;
    /*---------- STOP ENCODING  ----------*/

    /* we want to print the encoded data, so null-terminate it: */
    *c = 0;

    return output;
}

char* base64_decode(const char *input, u_int32_t max)
{
    /* set up a destination buffer large enough to hold the encoded data */
    char* output = (char*)malloc(max);
    /* keep track of our decoded position */
    char* c = output;
    /* store the number of bytes decoded by a single call */
    int cnt = 0;
    /* we need a decoder state */
    base64_decodestate s;

    /*---------- START DECODING ----------*/
    /* initialise the decoder state */
    base64_init_decodestate(&s);
    /* base64_decode the input data */
    cnt = base64_decode_block(input, strlen(input), c, &s);
    c += cnt;
    /* note: there is no base64_decode_blockend! */
    /*---------- STOP DECODING  ----------*/

    /* null-terminate it: */
    *c = 0;

    return output;
}