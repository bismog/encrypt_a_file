#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <arpa/inet.h> /* For htonl() */

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
    printf("LOAD PRIVATE KEY DONE\n");

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
    printf("READ EKLEN DONE\n");
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
    printf("READ EK DONE\n");
    if (fread(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, in_file) != 1)
    {
        perror("input file");
        retval = 4;
        goto out_free;
    }
    printf("IV length of aes 128 cbc: %d\n", EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    printf("IV length of aes 256 cbc: %d\n", EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    printf("IV length of aes 256 ctr: %d\n", EVP_CIPHER_iv_length(EVP_aes_256_ctr()));

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

// int main(int argc, char *argv[])
// {
//     FILE *rsa_pkey_file;
//     int rv;
// 
//     if (argc < 2)
//     {
//         fprintf(stderr, "Usage: %s <PEM RSA Private Key File>\n", argv[0]);
//         exit(1);
//     }
// 
//     rsa_pkey_file = fopen(argv[1], "rb");
//     if (!rsa_pkey_file)
//     {
//         perror(argv[1]);
//         fprintf(stderr, "Error loading PEM RSA Private Key File.\n");
//         exit(2);
//     }
// 
//     rv = do_evp_unseal(rsa_pkey_file, stdin, stdout);
// 
//     fclose(rsa_pkey_file);
//     return rv;
// }


int main(int argc, char *argv[])
{
    FILE *rsa_pkey_file;
    FILE *fin, *fout;
    int rv;
    char in_file[256] = "plain_file.enc";
    char out_file[256] = "plain_file.dec";

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <PEM RSA Private Key File>\n", argv[0]);
        exit(1);
    }

    rsa_pkey_file = fopen(argv[1], "rb");
    if (!rsa_pkey_file)
    {
        perror(argv[1]);
        fprintf(stderr, "Error loading PEM RSA Private Key File.\n");
        exit(2);
    }

    printf("OPEN PRIVATE KEY DONE\n");
    fin = fopen(in_file, "rb");
    fout = fopen(out_file, "wb");
    // rv = do_evp_unseal(rsa_pkey_file, stdin, stdout);
    rv = do_evp_unseal(rsa_pkey_file, fin, fout);

    fclose(rsa_pkey_file);
    return rv;
}

