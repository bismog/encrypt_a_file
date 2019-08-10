#include <stdio.h>
#include <string.h>
#include "base64.h"
#include <unistd.h>

#define FILE_LEN      256
#define RAW_BLK_LEN  1200
#define CODED_BLK_LEN  BASE64_ENCODE_OUT_SIZE(RAW_BLK_LEN)

int base64_encode_huge_file(const char *data_file)
{
	// char *buf = NULL;
    // char *buf_out = NULL;
	int len = 0;
	char buf[RAW_BLK_LEN] = {0};
    int len_out = 0;
    char buf_out[CODED_BLK_LEN] = {0};
    FILE *fin, *fout;
    char mid_file[FILE_LEN] = {0};
    int rv = 0;

    snprintf(mid_file, FILE_LEN, "%s.temp", data_file);
    printf("[ENCODE]Rename file to: %s.\n", mid_file);
    rename(data_file, mid_file);
    fin = fopen(mid_file, "rb");
    if (!fin)
    {
        perror(mid_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 10001;
        goto b64_encode_cleanup;
    }

	// fseek(fin, 0, SEEK_END);
	// len = ftell(fin);
	// rewind(fin);
	// if (0 == len){
    //     rv = 10003;
	// 	goto b64_cleanup;
	// }

	// buf = (char*)malloc(sizeof(char)*len+1);
	// memset(buf, 0, sizeof(char)*len+1);
	// if (len != fread(buf, 1, len, fin)){
    //     rv = 10004;
	// 	goto b64_cleanup;
	// }
    // fclose(fin);
    // fin = NULL;

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        rv = 10002;
        goto b64_encode_cleanup;
    }
    // // Length of encoded data
    // len_out = BASE64_ENCODE_OUT_SIZE(len);
    // // printf("source length: %d.\n", len);
    // // printf("encoded length: %d.\n", len_out);
    // buf_out = (char*)malloc(len_out+1);
    // if (len_out != base64_encode((unsigned char*)buf, len, buf_out)) {
    //     rv = 10005;
    //     goto b64_cleanup;
    // }
    while((len = fread(buf, 1, RAW_BLK_LEN, fin)) > 0) {
        len_out = BASE64_ENCODE_OUT_SIZE(len);
        if (len_out != base64_encode((unsigned char*)buf, len, buf_out)) {
            rv = 10005;
            goto b64_encode_cleanup;
        }

        if (fwrite(buf_out, len_out, 1, fout) != 1)
        {
            perror(data_file);
            rv = 10006;
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
        rename(mid_file, data_file);
    }
    else {
        unlink(mid_file);
    }
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

int base64_decode_huge_file(const char *data_file)
{
	int len = 0;
	char buf[CODED_BLK_LEN] = {0};
    int len_out = RAW_BLK_LEN;
    char buf_out[RAW_BLK_LEN] = {0};
	int pad_len = 0;
    FILE *fin, *fout;
    char mid_file[FILE_LEN] = {0};
    int rv = 0;

    snprintf(mid_file, FILE_LEN, "%s.temp", data_file);
    rename(data_file, mid_file);
    fin = fopen(mid_file, "rb");
    if (!fin)
    {
        perror(mid_file);
        fprintf(stderr, "Error Open Input File.\n");
        rv = 10001;
        goto b64_decode_cleanup;
    }

	// fseek(fin, 0, SEEK_END);
	// len = ftell(fin);
	// rewind(fin);
	// if (0 == len){
    //     rv = 10003;
	// 	goto b64_cleanup;
	// }

	// buf = (char*)malloc(sizeof(char)*len+1);
	// memset(buf, 0, sizeof(char)*len+1);
	// if (len != fread(buf, 1, len, fin)){
    //     rv = 10004;
	// 	goto b64_cleanup;
	// }
    // fclose(fin);
    // fin = NULL;

    fout = fopen(data_file, "wb");
    if (!fout)
    {
        perror(data_file);
        fprintf(stderr, "Error Open Output File.\n");
        rv = 10002;
        goto b64_decode_cleanup;
    }

    // // printf("source length: %d.\n", len);
    // // printf("decoded length: %d.\n", len_out);
    // buf_out = (char*)malloc(len_out+1);
    // if (0 != base64_decode((char*)buf, len, (unsigned char*)buf_out)) {
    //     // printf("DECODE FAILED!\n");
    //     rv = 10005;
    //     goto b64_decode_cleanup;
    // }
    while((len = fread(buf, 1, CODED_BLK_LEN, fin)) > 0) {
        // Length of decoded data
        // Note this size is the maximum size of decode data.
        // The real size may be BASE64_DECODE_OUT_SIZE(len)-1 or 
        // BASE64_DECODE_OUT_SIZE(len)-2. in other word,
        // it should be BASE64_DECODE_OUT_SIZE(len) minus number of 
        // character '='.
        if(len < CODED_BLK_LEN) {
            pad_len = padding_len(buf);
            if (255 == pad_len) {
                rv = 10005;
                goto b64_decode_cleanup;
            }
            len_out = BASE64_DECODE_OUT_SIZE(len) - pad_len;
        }
    
        if (0 != base64_decode((char*)buf, len, (unsigned char*)buf_out)) {
            rv = 10005;
            goto b64_decode_cleanup;
        }

        if (fwrite(buf_out, len_out, 1, fout) != 1)
        {
            perror(data_file);
            rv = 10006;
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
        rename(mid_file, data_file);
    }
    else {
        unlink(mid_file);
    }
    return rv;
}


int main(int argc, char *argv[]) {
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Data File To Be Encode/Decode>.\n", argv[0]);
        return 1;
    }

    //Encode huge file
    base64_encode_huge_file(argv[1]);

    //Decode huge file
    // base64_decode_huge_file(argv[1]);
    return 0;
}
