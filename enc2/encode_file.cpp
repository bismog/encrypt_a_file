#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "time.h"

#ifndef WIN32
// #include <arpa/inet.h> /* For htonl() */
#include <unistd.h>
#else
#include "include/getopt.h"
// #include <Winsock.h>
#endif

#define   FILE_LEN      256
#define   BUFFER_LEN     4096


int base64_encode_file(const char *data_file)
{
	int len = 0;
	char *buf = NULL;
    int enc_len = 0;
    char *enc_buf = NULL;
    FILE *fin, *fout;
    char temp_file[FILE_LEN] = {0};
    int rv = 0;

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

    // printf("DATA TO BE ENCODED.\n");
    // printf("===========================================\n");
    // for(int i=0;i<=len;i++) {
    //     printf("%x(%c)\t", buf[i], buf[i]);
    // }
    // printf("\n===========================================\n");

    // Length of encoded data
    enc_len = BASE64_ENCODE_OUT_SIZE(len);
    // printf("source length: %d.\n", len);
    // printf("encoded length: %d.\n", enc_len);
    enc_buf = (char*)malloc(enc_len+1);
    if (enc_len != base64_encode((unsigned char*)buf, len, enc_buf)) {
        rv = 10005;
        goto b64_cleanup;
    }

    // printf("DATA ENCODED.\n");
    // printf("===========================================\n");
    // for(int i=0;i<=enc_len;i++) {
    //     printf("%x(%c)\t", enc_buf[i], enc_buf[i]);
    // }
    // printf("\n===========================================\n");

    if (fwrite(enc_buf, enc_len, 1, fout) != 1)
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


int main(int argc, char *argv[]) {
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Data File>\n", argv[0]);
        exit(1);
    }
    else {
        printf("ENCODE FILE:%s.", argv[1]);
    }

    base64_encode_file(argv[1]);  

    return 0;
}
