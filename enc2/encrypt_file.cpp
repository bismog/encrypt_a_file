#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <arpa/inet.h> /* For htonl() */
#include <time.h>

#define FILE_LEN  256
#define BUFFER_LEN  4096

int do_evp_seal(FILE *rsa_pkey_file, FILE *in_file, FILE *out_file)
{
    int retval = 0;
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[BUFFER_LEN];
    unsigned char buffer_out[BUFFER_LEN + EVP_MAX_IV_LENGTH];
    size_t len;
    int len_out;
    unsigned char *ek = NULL;
    int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];

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

    /* First we write out the encrypted key length, then the encrypted key,
     ** then the iv (the IV length is fixed by the cipher we have chosen).
     **/

    eklen_n = htonl(eklen);
    if (fwrite(&eklen_n, sizeof eklen_n, 1, out_file) != 1)
    {
        perror("output file");
        retval = 5;
        goto out_free;
    }

    if (fwrite(ek, eklen, 1, out_file) != 1)
    {
        perror("output file");
        retval = 5;
        goto out_free;
    }

    if (fwrite(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, out_file) != 1)
    {
        perror("output file");
        retval = 5;
        goto out_free;
    }

    /* Now we process the input file and write the encrypted data to the
 *      * output file. */
    /* NOTE(chengml): Known issue: in file should has at least 16bytes of 
 *  data. or len of out will be 0. */
    while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
    {
        if (!EVP_SealUpdate(&ctx, buffer_out, &len_out, buffer, len))
        {
            fprintf(stderr, "EVP_SealUpdate: failed.\n");
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

    if (!EVP_SealFinal(&ctx, buffer_out, &len_out))
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

int main(int argc, char *argv[])
{
    FILE *rsa_pkey_file;
    FILE *fin, *fout;
    int rv;
    char temp_file[FILE_LEN] = {0};
    char data_file[FILE_LEN] = {0};
    int cur = 0;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <PEM RSA Public Key File> <Data File>\n", argv[0]);
        exit(1);
    }

    rsa_pkey_file = fopen(argv[1], "rb");
    if (!rsa_pkey_file)
    {
        perror(argv[1]);
        fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
        exit(2);
    }

    cur = time(NULL);
    strncpy(data_file, argv[2], FILE_LEN);
    snprintf(temp_file, FILE_LEN, "%s.%lu", data_file, cur);
    rename(data_file, temp_file);
    

    // rv = do_evp_seal(rsa_pkey_file, stdin, stdout);
    fin = fopen(temp_file, "rb");
    if (!fin)
    {
        perror(temp_file);
        fprintf(stderr, "Error Open Temp File:%s.\n", temp_file);
        exit(2);
    }
    
    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Data File:%s.\n", data_file);
        exit(2);
    }

    rv = do_evp_seal(rsa_pkey_file, fin, fout);
    fclose(rsa_pkey_file);
    fclose(fin);
    fclose(fout);
    if (0 != rv) {
        rename(temp_file, data_file);
    }
    else {
        unlink(temp_file);
    }
    return rv;
}
