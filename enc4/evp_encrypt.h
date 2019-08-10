#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
// #include "include/base64.h"
#include "base64.h"

#ifndef WIN32
#include <arpa/inet.h> /* For htonl() */
#include <unistd.h>
#else
#include "include/getopt.h"
#include <Winsock.h>
#define snprintf _snprintf
#endif

typedef unsigned int uint32;
typedef unsigned int uint32_t;

#define FILE_LEN  256
#define BUFFER_LEN  4096
#define RAW_BLK_LEN  1200
#define CODED_BLK_LEN  BASE64_ENCODE_OUT_SIZE(RAW_BLK_LEN)


#ifndef _ENCRYPT_H_ 
#define _ENCRYPT_H_

int evp_encrypt_file(const char *pubkey_file, const char *data_file);
int base64_encode_file(const char *data_file);
int evp_decrypt_file(const char *prikey_file, const char *data_file);
int base64_decode_file(const char *data_file);

#endif
