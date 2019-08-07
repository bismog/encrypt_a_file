#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "base64.h"

#ifndef WIN32
#include <arpa/inet.h> /* For htonl() */
#include <unistd.h>
#else
#include "include/getopt.h"
#include <Winsock.h>
#endif

#define   FILE_LEN      256
#define   BUF_LEN     4096

typedef struct _CACHE_DATA {
	unsigned char *data;
	int offset;
	int len;
}CACHE_DATA;

// int do_evp_seal(FILE *rsa_pkey_file, FILE *in_file, FILE *out_file)
int do_evp_seal(FILE *rsa_pkey_file, CACHE_DATA *pln, CACHE_DATA *enc)
{
    int retval = 0;
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[BUF_LEN];
    unsigned char buffer_out[BUF_LEN + EVP_MAX_IV_LENGTH];
    size_t len;
    int len_out = 0;
    int max_len = 0;
    int iv_len = 0;
    int rlen = 0;
    unsigned char *ek = NULL;
    int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    // CACHE_DATA *plain;
    // CACHE_DATA *enc = NULL;

    if (!PEM_read_RSA_PUBKEY(rsa_pkey_file, &rsa_pkey, NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Public Key File.\n");
        ERR_print_errors_fp(stderr);
        retval = 2;
        goto out;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        retval = 3;
        goto out;
    }

    EVP_CIPHER_CTX_init(&ctx);
    ek = (unsigned char*)malloc(EVP_PKEY_size(pkey));

    if (!EVP_SealInit(&ctx, EVP_aes_256_cbc(), &ek, &eklen, iv, &pkey, 1))
    {
        fprintf(stderr, "EVP_SealInit: failed.\n");
        retval = 3;
        goto out_free;
    }

    // header length + maximum encrypted data length
    iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    // max_len = 1 +\                                      // length of e-key
    //           eklen_n +\                                // e-key
    //           iv_len +\                                 // initial vector
    //           pln->len + BUF_LEN;                       // maximum e-data
    max_len = 1 + eklen_n + iv_len + pln->len + BUF_LEN;
	enc->data = (unsigned char *)malloc(max_len);
	if (enc->data == NULL) {
		free(enc);
		return 1;
	}
    memset(enc->data, 0, sizeof(unsigned char) * max_len);

    eklen_n = htonl(eklen);
    memcpy(enc->data, &eklen_n, sizeof(eklen_n));
    enc->offset += sizeof(eklen);
    memcpy(enc->data+enc->offset, ek, eklen);
    enc->offset += eklen;
    memcpy(enc->data+enc->offset, iv, iv_len);
    enc->offset += iv_len;
    /* First we write out the encrypted key length, then the encrypted key,
    ** then the iv (the IV length is fixed by the cipher we have chosen).
    */

    // eklen_n = htonl(eklen);
    // if (fwrite(&eklen_n, sizeof eklen_n, 1, out_file) != 1)
    // {
    //     perror("output file");
    //     retval = 5;
    //     goto out_free;
    // }
    // if (fwrite(ek, eklen, 1, out_file) != 1)
    // {
    //     perror("output file");
    //     retval = 5;
    //     goto out_free;
    // }
    // if (fwrite(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, out_file) != 1)
    // {
    //     perror("output file");
    //     retval = 5;
    //     goto out_free;
    // }

    /* Now we process the input file and write the encrypted data to the
    ** output file. 
    ** NOTE(chengml): Known issue: in file should has at least 16bytes of
    ** data. or len of out will be 0. */

    // while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
    // {

    // Here len means remained length
    rlen = pln->len;
    while (rlen > 0) {
        len = (rlen >= BUF_LEN) ? (BUF_LEN) : rlen;
        memcpy(buffer, pln->data+pln->offset, len);
        pln->offset += len;
            
        if (!EVP_SealUpdate(&ctx, buffer_out, &len_out, buffer, len))
        {
            fprintf(stderr, "EVP_SealUpdate: failed.\n");
            retval = 3;
            goto out_free;
        }
        memcpy(enc->data+enc->offset, buffer_out, len_out);
        enc->offset += len_out;
        rlen = (rlen >= BUF_LEN) ? (rlen-BUF_LEN) : 0;
        
    }

    // if (fwrite(buffer_out, len_out, 1, out_file) != 1)
    // {
    //     perror("output file");
    //     retval = 5;
    //     goto out_free;
    // }
    // }

    // if (ferror(in_file))
    // {
    //     perror("input file");
    //     retval = 4;
    //     goto out_free;
    // }
    //
    if (!EVP_SealFinal(&ctx, buffer_out, &len_out))
    {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        retval = 3;
        goto out_free;
    }
    memcpy(enc->data+enc->offset, buffer_out, len_out);
    enc->offset += len_out;
    enc->len = enc->offset;
    goto out;
    // if (!EVP_SealFinal(&ctx, buffer_out, &len_out))
    // {
    //     fprintf(stderr, "EVP_SealFinal: failed.\n");
    //     retval = 3;
    //     goto out_free;
    // }

    // if (fwrite(buffer_out, len_out, 1, out_file) != 1)
    // {
    //     perror("output file");
    //     retval = 5;
    //     goto out_free;
    // }

out_free:
    EVP_PKEY_free(pkey);
    free(ek);
    free(enc->data);
    free(enc);

out:
    return retval;
}

int evp_encrypt_file(const char *pubkey_file, const char *data_file)
{
    FILE *rsa_pkey_file;
    FILE *fin, *fout;
    int rv;
    int len = 0;
    // char temp_file[FILE_LEN] = {0};
    CACHE_DATA *pln = NULL;
    CACHE_DATA *enc = NULL;

    rsa_pkey_file = fopen(pubkey_file, "rb");
    if (!rsa_pkey_file)
    {
        perror(pubkey_file);
        fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
        rv = 1;
        goto evp_encrypt_clean;
    }

	pln = (CACHE_DATA *)malloc(sizeof(CACHE_DATA));
	if (pln == NULL) {
        rv = 1;
        goto evp_encrypt_clean;
    }
    memset(pln, 0, sizeof(CACHE_DATA));

	enc = (CACHE_DATA *)malloc(sizeof(CACHE_DATA));
	if (enc == NULL) {
        rv = 1;
        goto evp_encrypt_clean;
    }
    memset(enc, 0, sizeof(CACHE_DATA));

    // Get source file length
    fin = fopen(data_file, "rb");
    if (!fin)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 1;
        goto evp_encrypt_clean;
    }
	fseek(fin, 0, SEEK_END);
	pln->len = ftell(fin);
	rewind(fin);
	if (0 == pln->len){
        rv = 1;
        goto evp_encrypt_clean;
    }

	pln->data = (unsigned char *)malloc(pln->len);
	if (pln->data == NULL) {
        rv = 1;
        goto evp_encrypt_clean;
	}
    memset(pln->data, 0, sizeof(unsigned char) * pln->len);
    
    // snprintf(temp_file, FILE_LEN, "%s.%u", data_file, time(NULL));
    // printf("[ENCRYPT]Rename file to: %s.\n", temp_file);
    // rename(data_file, temp_file);
    // fin = fopen(temp_file, "rb");
    // if (!fin)
    // {
    //     perror(temp_file);
    //     fprintf(stderr, "Error Open Input File.\n");
    //     return 1;
    // }
    fin = fopen(data_file, "rb");
    if (!fin)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 1;
        goto evp_encrypt_clean;
    }
    
    len = fread(pln->data, pln->len, 1, fin);
    if (len != 1) {
        rv = 1;
        goto evp_encrypt_clean;
    }
    fclose(fin);
    fin = NULL;

    // rv = do_evp_seal(rsa_pkey_file, fin, fout);
    rv = do_evp_seal(rsa_pkey_file, pln, enc);
    if (rv != 0) {
        rv = 1;
        goto evp_encrypt_clean;
    }

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        rv = 1;
        goto evp_encrypt_clean;
    }

    if (fwrite(enc->data, enc->len, 1, fout) != 1)
    {
        perror("output file");
        rv = 1;
        goto evp_encrypt_clean;
    }

evp_encrypt_clean:
    if(pln->data) {
        free(pln->data);
    }
    if(pln) {
        free(pln);
    }

    if(enc->data) {
        free(enc->data);
    }
    if(enc) {
        free(enc);
    }
    fclose(rsa_pkey_file);
    rsa_pkey_file = NULL;
    if(fin) {
        fclose(fin);
        fin = NULL;
    }
    if(fout) {
        fclose(fout);
        fout = NULL;
    }
    return rv;
}


int base64_encode_file(const char *data_file)
{
	int len = 0;
	char *buf = NULL;
    int enc_len = 0;
    char *enc_buf = NULL;
    FILE *fin, *fout;
    // char temp_file[FILE_LEN] = {0};
    int rv = 0;

    // snprintf(temp_file, FILE_LEN, "%s.%u", data_file, time(NULL));
    // printf("[ENCODE]Rename file to: %s.\n", temp_file);
    // rename(data_file, temp_file);
    fin = fopen(data_file, "rb");
    if (!fin)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 10001;
        goto b64_cleanup;
    }

	fseek(fin, 0, SEEK_END);
	len = ftell(fin);
	rewind(fin);
	if (0 == len){
        rv = 10003;
		goto b64_cleanup;
	}

	buf = (char*)malloc(sizeof(char)*len+1);
	memset(buf, 0, sizeof(char)*len+1);
	if (len != fread(buf, 1, len, fin)){
        rv = 10004;
		goto b64_cleanup;
	}
    fclose(fin);
    fin = NULL;

    // Length of encoded data
    enc_len = BASE64_ENCODE_OUT_SIZE(len);
    // printf("source length: %d.\n", len);
    // printf("encoded length: %d.\n", enc_len);
    enc_buf = (char*)malloc(enc_len+1);
    if (enc_len != base64_encode((unsigned char*)buf, len, enc_buf)) {
        rv = 10005;
        goto b64_cleanup;
    }

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        rv = 10002;
        goto b64_cleanup;
    }

    if (fwrite(enc_buf, enc_len, 1, fout) != 1)
    {
        perror(data_file);
        rv = 10006;
        goto b64_cleanup;
    }

b64_cleanup:
    if(enc_buf) {
        free(enc_buf);
    }
    if(fin) {
        fclose(fin);
        fin = NULL;
    }
    if(fout) {
        fclose(fout);
        fout = NULL;
    }
    return rv;
}

int do_evp_unseal(FILE *rsa_pkey_file, FILE *in_file, FILE *out_file)
{
    int retval = 0;
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[BUF_LEN];
    unsigned char buffer_out[BUF_LEN + EVP_MAX_IV_LENGTH];
    size_t len;
    int len_out;
    unsigned char *ek;
    unsigned int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if (!PEM_read_RSAPrivateKey(rsa_pkey_file, &rsa_pkey, NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Private Key File.\n");
        ERR_print_errors_fp(stderr);
        retval = 2;
        goto out;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        retval = 3;
        goto out;
    }

    EVP_CIPHER_CTX_init(&ctx);
    ek = (unsigned char*)malloc(EVP_PKEY_size(pkey));

    /* First need to fetch the encrypted key length, encrypted key and IV */

    if (fread(&eklen_n, sizeof eklen_n, 1, in_file) != 1)
    {
        perror("input file");
        retval = 4;
        goto out_free;
    }
    eklen = ntohl(eklen_n);
    if (eklen > EVP_PKEY_size(pkey))
    {
        fprintf(stderr, "Bad encrypted key length (%u > %d)\n", eklen,
            EVP_PKEY_size(pkey));
        retval = 4;
        goto out_free;
    }
    if (fread(ek, eklen, 1, in_file) != 1)
    {
        perror("input file");
        retval = 4;
        goto out_free;
    }
    if (fread(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, in_file) != 1)
    {
        perror("input file");
        retval = 4;
        goto out_free;
    }

    if (!EVP_OpenInit(&ctx, EVP_aes_256_cbc(), ek, eklen, iv, pkey))
    {
        fprintf(stderr, "EVP_OpenInit: failed.\n");
        retval = 3;
        goto out_free;
    }

    while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
    {
        if (!EVP_OpenUpdate(&ctx, buffer_out, &len_out, buffer, len))
        {
            fprintf(stderr, "EVP_OpenUpdate: failed.\n");
            retval = 3;
            goto out_free;
        }

        if (fwrite(buffer_out, len_out, 1, out_file) != 1)
        {
            perror("output file");
            retval = 5;
            goto out_free;
        }
    }

    if (ferror(in_file))
    {
        perror("input file");
        retval = 4;
        goto out_free;
    }

    if (!EVP_OpenFinal(&ctx, buffer_out, &len_out))
    {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        retval = 3;
        goto out_free;
    }

    if (fwrite(buffer_out, len_out, 1, out_file) != 1)
    {
        perror("output file");
        retval = 5;
        goto out_free;
    }

    out_free:
    EVP_PKEY_free(pkey);
    free(ek);

    out:
    return retval;
}

int main(int argc, char *argv[]) {
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <PEM RSA Public Key File> <Data File>\n", argv[0]);
        exit(1);
    }
    else {
        printf("ENCRYPT FILE:%s WITH KEY:%s.", argv[2], argv[1]);
    }

    // if( 0 == evp_encrypt_file(argv[1], argv[2])) {
    //     // printf("ENCRYPT OK");
    //     base64_encode_file(argv[2]);  
    // }
    evp_encrypt_file(argv[1], argv[2]);
    base64_encode_file(argv[2]);  
    return 0;
}
