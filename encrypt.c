#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "encrypt.h"


void encrypt_init()
{
	static int aesinited = 0;
	if (aesinited == 0) {
		srand(time(NULL));
		aes_init();
		aesinited = 1;
	}
}

static void gen_key(unsigned char *key, long len) {
	const char k[] = {'n', 0xc0, 'w', '@', 'u', 0x57, 'b', 0x80, 
		'o', 0, 's', '*', 'h', 0x54, 'a', 0};
	unsigned char blen = len & 0xff;
	int i=0, j=0;
	for (i=0; i<2; i++)
	{
		for (j=0; j<16; j++) 
		{
			key[i*16+j] = k[j] ^ (blen++);
		}
	}
}

const char *enc_prefix = "WLUS";

ENC_FILE * dec_rd_cleantext(FILE *fp, long len) {
	int i=0;
	ENC_FILE * enc_f = (ENC_FILE *)malloc(sizeof(ENC_FILE));
	if (enc_f == NULL)
		return NULL;
	enc_f->data = (unsigned char *)malloc(len);
	if (enc_f->data == NULL) {
		free(enc_f);
		return NULL;
	}
	fseek(fp, 0, SEEK_SET);
	
	enc_f->offset = 0;
	enc_f->len = 0;
	
	while( enc_f->len < len && (i = fread(enc_f->data+enc_f->len, 1, len - enc_f->len, fp)) > 0 ) {
		enc_f->len += i;
	}
  
	return enc_f;
}

ENC_FILE * dec_file(FILE *fp, long len) {
	aes_encrypt_ctx ctx[1];
	unsigned char iv[16]; /* initialisation vector */
	unsigned char buf[200], key[32];
	int i=0;
	
	ENC_FILE * enc_f = (ENC_FILE *)malloc(sizeof(ENC_FILE));
	if (enc_f == NULL)
		return NULL;
	enc_f->data = (unsigned char *)malloc(len);
	if (enc_f->data == NULL) {
		free(enc_f);
		return NULL;
	}
	enc_f->offset = 0;
	enc_f->len = 0;
	
	/* read initialization vector from file */
	fread(iv, 1, 16, fp);
	len -= (16 + strlen(enc_prefix));
	gen_key(key, len);
	aes_encrypt_key256(key, ctx);
	
	while(len > enc_f->len && (i = fread(buf, 1, sizeof(buf), fp)) > 0) {
		aes_ofb_crypt(buf, enc_f->data+enc_f->len, i, iv, ctx);
		enc_f->len += i;
	}
	
	return enc_f;
}

ENC_FILE * dec_open(const char *file) {
	ENC_FILE * enc_f = NULL;
	unsigned char buf[20];
	long len;

	FILE *fp = fopen(file, "rb");
	if (fp == NULL) return NULL;
	
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	if (len < strlen(enc_prefix) + 16) { //too short
		enc_f = dec_rd_cleantext(fp, len);
		fclose(fp);
		return enc_f;
	}
	fseek(fp, 0, SEEK_SET);
	
	/* encrypt file should begin with WLUS */
	fread(buf, 1, strlen(enc_prefix), fp);
	if (memcmp(buf, enc_prefix, strlen(enc_prefix)) != 0) { // not encrypt file
		enc_f = dec_rd_cleantext(fp, len);
		fclose(fp);
		return enc_f;
	}
	
	enc_f = dec_file(fp, len);
	fclose(fp);
	return enc_f;
}

void dec_close(ENC_FILE *enc_f) {
	if (enc_f == NULL) return;

	free(enc_f->data);
	enc_f->data = NULL;
	free(enc_f);
}

char * dec_read_line(ENC_FILE *enc_f, char *buf, int max_len) {
	int len = 0;
	max_len -= 1; //for 0 string end char
	while (enc_f->offset < enc_f->len && len < max_len) {
		buf[len] = enc_f->data[enc_f->offset++];
		if (buf[len] == '\n') {
			buf[len+1] = 0;
			return buf;
		}
		len++;
	}
	if (len == 0) return NULL;
	buf[len] = 0;
	return buf;
}

int dec_read(ENC_FILE *enc_f, char *buf, int max_len) {
	int len = 0;
	int kept;
	if (enc_f == NULL) return 0;
	
	kept = enc_f->len - enc_f->offset;
	
	len = max_len > kept ? kept : max_len;
	if (len == 0) return 0;
	
	memcpy(buf, enc_f->data+enc_f->offset, len);
	enc_f->offset += len;
	
	return len;
}

int encrypt_file(const char *fileIn, const char *fileOut) {
	int i;
	aes_encrypt_ctx ctx[1];
	unsigned char iv[16]; /* initialisation vector */
	unsigned char inBuffer[200], outBuffer[200];
	unsigned char key[32];
	long len;
	FILE *outFile = NULL;
	
	FILE *inFile = fopen(fileIn, "rb");
	if (inFile == NULL) 
		return -1;
	fseek(inFile, 0, SEEK_END);
	len = ftell(inFile);
	fseek(inFile, 0, SEEK_SET);
	
	outFile = fopen(fileOut, "wb");
	if (outFile == NULL) {
		fclose(inFile);
		return -2;
	}
	
	/* pick a random initialisation vector, and write it to file header */
	for(i = 0; i < 16; ++i)
		iv[i] = rand() & 0xFF;
	fwrite(enc_prefix, 1, strlen(enc_prefix), outFile);
	fwrite(iv, 1, 16, outFile);
	
	gen_key(key, len);
    printf("%s\n", key);
	aes_encrypt_key256(key, ctx);
	
	while((i = fread(inBuffer, 1, sizeof(inBuffer), inFile)) > 0) {
		aes_ofb_crypt(inBuffer, outBuffer, i, iv, ctx);
		fwrite(outBuffer, 1, i, outFile);
	}
	
	fclose(inFile);
	fclose(outFile);
	return 0;
}

int decrypt_file(const char *fileIn, const char *fileOut) {
	int i;
	aes_encrypt_ctx ctx[1];
	unsigned char iv[16]; /* initialisation vector */
	unsigned char inBuffer[200], outBuffer[200];
	unsigned char key[32];
	long len;
	FILE *outFile = NULL;
	
	FILE *inFile = fopen(fileIn, "rb");
	if (inFile == NULL) 
		return -1;
	fseek(inFile, 0, SEEK_END);
	len = ftell(inFile);
	fseek(inFile, 0, SEEK_SET);
	
	outFile = fopen(fileOut, "wb");
	if (outFile == NULL) {
		fclose(inFile);
		return -2;
	}
	
	/* check file header */
	if(fread(iv, 1, strlen(enc_prefix), inFile) < strlen(enc_prefix)) {
		fclose(inFile);
		fclose(outFile);
		return 1;
	}
	if (memcmp(iv, enc_prefix, strlen(enc_prefix)) != 0){
		fclose(inFile);
		fclose(outFile);
		return 1;
	}
	
	/* read initialization vector from file */
	if(fread(iv, 1, 16, inFile) < 16){
		fclose(inFile);
		fclose(outFile);
		return 1;
	}
	
	gen_key(key, len - strlen(enc_prefix) - 16);
    printf("%s\n", key);
	aes_encrypt_key256(key, ctx);
	
	while((i = fread(inBuffer, 1, sizeof(inBuffer), inFile)) > 0) {
		aes_ofb_crypt(inBuffer, outBuffer, i, iv, ctx);
		fwrite(outBuffer, 1, i, outFile);
	}
	
	fclose(inFile);
	fclose(outFile);
	return 0;
}

int main() 
{
    char in_file[256] = "/tmp/tmp/virus.xxx.log";
    char out_file[256] = "/tmp/tmp/virus.xxx.log.enc";
    char out_file2[256] = "/tmp/tmp/virus.xxx.log.dec";
    

    encrypt_file(in_file, out_file);
    decrypt_file(out_file, out_file2);    
    return 0;
}
