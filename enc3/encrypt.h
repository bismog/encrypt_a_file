#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#include "aes.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#ifndef _ENCRYPT_H_ 
#define _ENCRYPT_H_

typedef struct _ENC_FILE {
	unsigned char *data;
	int offset;
	int len;
}ENC_FILE;

void encrypt_init();

ENC_FILE * dec_open(const char *file);
void dec_close(ENC_FILE *enc_f);
char * dec_read_line(ENC_FILE *enc_f, char *buf, int max_len);
int dec_read(ENC_FILE *enc_f, char *buf, int max_len);

int encrypt_file(const char *fileIn, const char *fileOut);
int decrypt_file(const char *fileIn, const char *fileOut);

#endif

#if defined(__cplusplus)
}
#endif
