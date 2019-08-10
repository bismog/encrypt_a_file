#include "evp_encrypt.h"

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
        retval = 1001;
        goto out;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        retval = 1002;
        goto out;
    }

    EVP_CIPHER_CTX_init(&ctx);
    ek = (unsigned char*)malloc(EVP_PKEY_size(pkey));

    if (!EVP_SealInit(&ctx, EVP_aes_256_cbc(), &ek, &eklen, iv, &pkey, 1))
    {
        fprintf(stderr, "EVP_SealInit: failed.\n");
        retval = 1003;
        goto out_free;
    }

    /* First we write out the encrypted key length, then the encrypted key,
    ** then the iv (the IV length is fixed by the cipher we have chosen).
    */

    eklen_n = htonl(eklen);
    if (fwrite(&eklen_n, sizeof eklen_n, 1, out_file) != 1)
    {
        perror("output file");
        retval = 1004;
        goto out_free;
    }
    if (fwrite(ek, eklen, 1, out_file) != 1)
    {
        perror("output file");
        retval = 1005;
        goto out_free;
    }
    if (fwrite(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, out_file) != 1)
    {
        perror("output file");
        retval = 1006;
        goto out_free;
    }

    /* Now we process the input file and write the encrypted data to the
    ** output file. 
    ** NOTE(chengml): Known issue: in file should has at least 16bytes of
    ** data. or len of out will be 0. */

    while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
    {
        if (!EVP_SealUpdate(&ctx, buffer_out, &len_out, buffer, len))
        {
            fprintf(stderr, "EVP_SealUpdate: failed.\n");
            retval = 1007;
            goto out_free;
        }

        if (fwrite(buffer_out, len_out, 1, out_file) != 1)
        {
            perror("output file");
            retval = 1008;
            goto out_free;
        }
    }

    if (ferror(in_file))
    {
        perror("input file");
        retval = 1009;
        goto out_free;
    }

    if (!EVP_SealFinal(&ctx, buffer_out, &len_out))
    {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        retval = 1010;
        goto out_free;
    }

    if (fwrite(buffer_out, len_out, 1, out_file) != 1)
    {
        perror("output file");
        retval = 1011;
        goto out_free;
    }

    out_free:
    EVP_PKEY_free(pkey);
    free(ek);

    out:
    return retval;
}

int evp_encrypt_file(const char *pubkey_file, const char *data_file)
{
    FILE *rsa_pkey_file;
    FILE *fin, *fout;
    int rv;
    char temp_file[FILE_LEN] = {0};

    rsa_pkey_file = fopen(pubkey_file, "rb");
    if (!rsa_pkey_file)
    {
        perror(pubkey_file);
        fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
        return 20001;
    }

    snprintf(temp_file, FILE_LEN, "%s.temp", data_file);
    rename(data_file, temp_file);
    fin = fopen(temp_file, "rb");
    if (!fin)
    {
        perror(temp_file);
        fprintf(stderr, "Error Open Input File.\n");
        fclose(rsa_pkey_file);
        rename(temp_file, data_file);
        return 20002;
    }

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        fclose(rsa_pkey_file);
        fclose(fin);
        rename(temp_file, data_file);
        return 20003;
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


int base64_encode_file(const char *data_file)
{
    int len = 0;
    char buf[RAW_BLK_LEN+1] = {0};
    int len_out = 0;
    char buf_out[CODED_BLK_LEN+1] = {0};
    FILE *fin, *fout;
    char temp_file[FILE_LEN] = {0};
    int rv = 0;

    snprintf(temp_file, FILE_LEN, "%s.temp", data_file);
    rename(data_file, temp_file);
    fin = fopen(temp_file, "rb");
    if (!fin)
    {
        perror(temp_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 10001;
        goto b64_encode_cleanup;
    }

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        rv = 10002;
        goto b64_encode_cleanup;
    }

    
    while((len = fread(buf, 1, RAW_BLK_LEN, fin)) > 0) {
        len_out = BASE64_ENCODE_OUT_SIZE(len);
        if (len_out != base64_encode((unsigned char*)buf, len, buf_out)) {
            rv = 10003;
            goto b64_encode_cleanup;
        }

        if (fwrite(buf_out, len_out, 1, fout) != 1)
        {
            perror(data_file);
            rv = 10004;
            goto b64_encode_cleanup;
        }
    }

b64_encode_cleanup:
    if(fin) {
        fclose(fin);
    }
    if(fout) {
        fclose(fout);
    }
    if(rv) {
        rename(temp_file, data_file);
    }
    else {
        unlink(temp_file);
    }
    return rv;
}

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
        retval = 1001;
        goto out;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        retval = 1002;
        goto out;
    }

    EVP_CIPHER_CTX_init(&ctx);
    ek = (unsigned char*)malloc(EVP_PKEY_size(pkey));

    /* First need to fetch the encrypted key length, encrypted key and IV */
    if (fread(&eklen_n, sizeof eklen_n, 1, in_file) != 1)
    {
        perror("input file");
        retval = 1003;
        goto out_free;
    }

    eklen = ntohl(eklen_n);
    if (eklen > EVP_PKEY_size(pkey))
    {
        fprintf(stderr, "Bad encrypted key length (%u > %d)\n", eklen,
            EVP_PKEY_size(pkey));
        retval = 1004;
        goto out_free;
    }
    if (fread(ek, eklen, 1, in_file) != 1)
    {
        perror("input file");
        retval = 1005;
        goto out_free;
    }

    if (fread(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, in_file) != 1)
    {
        perror("input file");
        retval = 1006;
        goto out_free;
    }

    if (!EVP_OpenInit(&ctx, EVP_aes_256_cbc(), ek, eklen, iv, pkey))
    {
        fprintf(stderr, "EVP_OpenInit: failed.\n");
        retval = 1007;
        goto out_free;
    }

    while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
    {
        if (!EVP_OpenUpdate(&ctx, buffer_out, &len_out, buffer, len))
        {
            fprintf(stderr, "EVP_OpenUpdate: failed.\n");
            retval = 1008;
            goto out_free;
        }

        if (fwrite(buffer_out, len_out, 1, out_file) != 1)
        {
            perror("output file");
            retval = 1009;
            goto out_free;
        }
    }

    if (ferror(in_file))
    {
        perror("input file");
        retval = 1010;
        goto out_free;
    }

    if (!EVP_OpenFinal(&ctx, buffer_out, &len_out))
    {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        retval = 1011;
        goto out_free;
    }

    if (len_out != 0) {
        if (fwrite(buffer_out, len_out, 1, out_file) != 1)
        {
            perror("output file");
            retval = 1012;
            goto out_free;
        }
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
        return 1001;
    }

    snprintf(temp_file, FILE_LEN, "%s.temp", data_file);
    rename(data_file, temp_file);
    fin = fopen(temp_file, "rb");
    if (!fin)
    {
        perror(temp_file);
        fprintf(stderr, "Error Open Input File.\n");
        fclose(rsa_pkey_file);
        rename(temp_file, data_file);
        return 1002;
    }

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        fclose(rsa_pkey_file);
        fclose(fin);
        rename(temp_file, data_file);
        return 1003;
    }

    rv = do_evp_unseal(rsa_pkey_file, fin, fout);

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

int padding_len(const char *data, int len) {
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

int real_len(char *str, int len) {
    char ch;
    int len_out=0;

    while (((ch = (unsigned char)*str) != '\0') && \
           ((ch = (unsigned char)*str) != '\n') && \
           ((ch = (unsigned char)*str) != '\r')) {
        if(len_out >= len) {
            return len;
        }
        str++;
        len_out++;
    }

    return len_out;
}

int base64_decode_file(const char *data_file)
{
	int len = 0;
	char buf[CODED_BLK_LEN+1] = {0};
    int len_out = RAW_BLK_LEN;
    char buf_out[RAW_BLK_LEN+1] = {0};
	int pad_len = 0;
    FILE *fin, *fout;
    char temp_file[FILE_LEN] = {0};
    int rv = 0;

    snprintf(temp_file, FILE_LEN, "%s.temp", data_file);
    rename(data_file, temp_file);
    fin = fopen(temp_file, "rb");
    if (!fin)
    {
        perror(temp_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 10001;
        goto b64_decode_cleanup;
    }

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        rv = 10002;
        goto b64_decode_cleanup;
    }

    while((len = fread(buf, 1, CODED_BLK_LEN, fin)) > 0) {
        // Length of decoded data
        // Note this size is the maximum size of decode data.
        // The real size may be BASE64_DECODE_OUT_SIZE(len)-1 or 
        // BASE64_DECODE_OUT_SIZE(len)-2. in other word,
        // it should be BASE64_DECODE_OUT_SIZE(len) minus number of 
        // character '='.
        len = real_len(buf, len);
        if(len < CODED_BLK_LEN) {
            pad_len = padding_len(buf, len);
            if (255 == pad_len) {
                rv = 10003;
                goto b64_decode_cleanup;
            }
            len_out = BASE64_DECODE_OUT_SIZE(len) - pad_len;
        }
    
        if (0 != base64_decode((char*)buf, len, (unsigned char*)buf_out)) {
            rv = 10004;
            goto b64_decode_cleanup;
        }

        if (fwrite(buf_out, len_out, 1, fout) != 1)
        {
            perror(data_file);
            rv = 10005;
            goto b64_decode_cleanup;
        }
    }

b64_decode_cleanup:
    if(fin) {
        fclose(fin);
    }
    if(fout) {
        fclose(fout);
    }
    if(rv) {
        rename(temp_file, data_file);
    }
    else {
        unlink(temp_file);
    }
    return rv;
}


// Ether build target as encfile or decfile

#if 0
int main(int argc, char *argv[]) {
    int rv = 0;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Public Key File> <Data File>\n", argv[0]);
        exit(1);
    }
    else {
        printf("FILE:%s.\n", argv[2]);
    }

    if((rv = evp_encrypt_file(argv[1], argv[2])) != 0) {
        printf("SORRY! ENCRYPT FAILED, rv: %d.\n", rv);
    }
    else {
        rv = base64_encode_file(argv[2]);
        if(rv != 0) {
            printf("SORRY! ENCODE FAILED, rv: %d.\n", rv);
        }
    }

    return 0;
}
#endif

#if 0
int main(int argc, char *argv[]) {
    int rv = 0;

    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <Private Key File> <Data File>\n", argv[0]);
        exit(1);
    }
    else {
        printf("FILE:%s.\n", argv[2]);
    }

    if((rv = base64_decode_file(argv[2])) != 0) {
        printf("SORRY! DECODE FAILED, rv: %d.\n", rv);
    }
    else {
        rv = evp_decrypt_file(argv[1], argv[2]);  
        if(rv != 0) {
            printf("SORRY! DECRYPT FAILED, rv: %d.\n", rv);
        }
    }

    return 0;
}
#endif
