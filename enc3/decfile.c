#include "encrypt.h"

int main() {
    char infile[256] = "./crypt_file";
    char outfile[256] = "./plain_file";

    decrypt_file(infile, outfile);

    // ENC_FILE *fp = dec_open(infile);
    // if (fp == NULL)
    //     return 0;

    // int ret = 0;
    // char line[256];
    // line[sizeof(line)-1] = 0;

    // int i = 0;
    // while (dec_read_line(fp, line, sizeof(line)-1)) {
    //     printf("line %d: %s\n", i, line);
    //     i++;
    // }
    // dec_close(fp);
    return 0;
}
