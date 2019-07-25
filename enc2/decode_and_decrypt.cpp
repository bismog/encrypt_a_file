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

#define FILE_LEN      256
#define BUFFER_LEN  4096

int do_evp_unseal(FILE *rsa_pkey_file, FILE *in_file, FILE *out_file)
{
    int retval = 0;
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[BUFFER_LEN];
    unsigned char buffer_out[BUFFER_LEN + EVP_MAX_IV_LENGTH];
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
    // printf("LOAD PRIVATE KEY DONE\n");

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
    // printf("READ EKLEN DONE\n");
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
    // printf("READ EK DONE\n");
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

int evp_decrypt_file(const char *prikey_file, const char *data_file)
{
    FILE *rsa_pkey_file;
    FILE *fin, *fout;
    int rv;
    char temp_file[FILE_LEN] = {0};

    rsa_pkey_file = fopen(prikey_file, "rb");
    if (!rsa_pkey_file)
    {
        perror(prikey_file);
        fprintf(stderr, "Error loading PEM RSA Private Key File.\n");
        return 1;
    }

    snprintf(temp_file, FILE_LEN, "%s.%u", data_file, time(NULL));
    rename(data_file, temp_file);
    fin = fopen(temp_file, "rb");
    if (!fin)
    {
        perror(temp_file);
        fprintf(stderr, "Error Open Input File.\n");
        fclose(rsa_pkey_file);
        return 1;
    }

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        fclose(rsa_pkey_file);
        fclose(fin);
        return 1;
    }

    rv = do_evp_unseal(rsa_pkey_file, fin, fout);

    fclose(rsa_pkey_file);
    fclose(fin);
    fclose(fout);
    return rv;
}

int padding_len(const char *data) {
    int len = strlen(data);
    if (len <= 2) {
        return 255;
    }
    // printf("Last two data: %x(%c) %x(%c)\n", data[len-2], data[len-2], data[len-1], data[len-1]);
    if (data[len-2] == '=') {
        return 2;
    }
    else if (data[len-1] == '=') {
        return 1;
    }
    return 0;
}

int base64_decode_file(const char *data_file)
{
	int len = 0;
	int pad_len = 0;
	char *buf = NULL;
    int dec_len = 0;
    char *dec_buf = NULL;
    FILE *fin, *fout;
    char temp_file[FILE_LEN] = {0};
    int rv = 0;
    int out_len = 0;

    snprintf(temp_file, FILE_LEN, "%s.%u", data_file, time(NULL));
    rename(data_file, temp_file);
    fin = fopen(temp_file, "rb");
    if (!fin)
    {
        perror(temp_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 10001;
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

	fseek(fin, 0, SEEK_END);
	len = ftell(fin);
	rewind(fin);
	if (0 == len){
		fclose(fin);
		fin = NULL;
		remove(temp_file);
        rv = 10003;
		goto b64_cleanup;
	}

	buf = (char*)malloc(sizeof(char)*len+1);
	memset(buf, 0, sizeof(char)*len+1);
	if (len != fread(buf, 1, len, fin)){
        perror(temp_file);
        rv = 10004;
		goto b64_cleanup;
	}

    // Length of decoded data
    // Note this size is the maximum size of decode data.
    // The real size may be BASE64_DECODE_OUT_SIZE(len)-1 or 
    // BASE64_DECODE_OUT_SIZE(len)-2. in other word,
    // it should be BASE64_DECODE_OUT_SIZE(len) minus number of 
    // character '='.
    pad_len = padding_len(buf);
    if (255 == pad_len) {
        rv = 10005;
        goto b64_cleanup;
    }
    dec_len = BASE64_DECODE_OUT_SIZE(len) - pad_len;
    // printf("source length: %d.\n", len);
    // printf("decoded length: %d.\n", dec_len);
    dec_buf = (char*)malloc(dec_len+1);
    if (0 != base64_decode((char*)buf, len, (unsigned char*)dec_buf)) {
        // printf("DECODE FAILED!\n");
        rv = 10005;
        goto b64_cleanup;
    }

    if (fwrite(dec_buf, dec_len, 1, fout) != 1)
    {
        perror(data_file);
        rv = 10006;
        goto b64_cleanup;
    }

    unlink(temp_file);

b64_cleanup:
    fclose(fin);
    fclose(fout);
    rename(temp_file, data_file);
    return rv;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <PEM RSA Private Key File> <Data File>\n", argv[0]);
        exit(1);
    }
    else {
        printf("DECRYPT FILE:%s WITH KEY:%s.", argv[2], argv[1]);
    }

    if( 0 == base64_decode_file(argv[2])) {
        // printf("DECODE OK, DECRYPT FILE..\n");
        evp_decrypt_file(argv[1], argv[2]);  
    }

    return 0;

}

