//
// Created by almir on 3/27/17.
//

#ifndef SIRIDB_SERVER_BASE64_H
#define SIRIDB_SERVER_BASE64_H


#include <sys/types.h>

char* base64_encode(const char *input, u_int32_t max);
char* base64_decode(const char *input, u_int32_t max);

#endif //SIRIDB_SERVER_BASE64_H
