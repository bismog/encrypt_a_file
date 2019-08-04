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

#define FILE_LEN      256
#define BUFFER_LEN  4096

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
    unsigned char *dec_buf = NULL;
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

    // printf("DATA TO BE DECODED.\n");
    // printf("===========================================\n");
    // for(int i=0;i<=len;i++) {
    //     printf("%x(%c)\t", buf[i], buf[i]);
    // }
    // printf("\n===========================================\n");

    // Length of decoded data
    // Note this size is the maximum size of decode data.
    // The real size may be BASE64_DECODE_OUT_SIZE(len)-1 or 
    // BASE64_DECODE_OUT_SIZE(len)-2. in other word,
    // it should be BASE64_DECODE_OUT_SIZE(len) minus number of 
    // character '='.
    // printf("source length: %d.\n", len);
    // printf("max decoded length: %d.\n", BASE64_DECODE_OUT_SIZE(len));
    pad_len = padding_len(buf);
    if (255 == pad_len) {
        rv = 10005;
        goto b64_cleanup;
    }
    dec_len = BASE64_DECODE_OUT_SIZE(len) - pad_len;
    // printf("real decoded length: %d.\n", dec_len);
    dec_buf = (unsigned char*)malloc(dec_len+1);
    if (0 != base64_decode((char*)buf, len, dec_buf)) {
        // printf("DECODE FAILED!\n");
        rv = 10006;
        goto b64_cleanup;
    }

    // printf("DATA DECODED.\n");
    // printf("===========================================\n");
    // for(int i=0;i<=dec_len;i++) {
    //     printf("%x(%c)\t", dec_buf[i], dec_buf[i]);
    // }
    // printf("\n===========================================\n");

    if (fwrite(dec_buf, dec_len, 1, fout) != 1)
    {
        perror(data_file);
        rv = 10007;
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
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Data File>\n", argv[0]);
        exit(1);
    }
    else {
        printf("DECODE FILE:%s.", argv[1]);
    }

    base64_decode_file(argv[1]);

    return 0;

}

