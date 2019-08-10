#include "encrypt.h"

int main(int argc, char *argv[]) {
#if 0
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
#else
    char outfile[512] = {0};

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Data File>\n", argv[0]);
        fprintf(stderr, "       This will generate decrypt file \"xxx.dec\".\n");
        exit(1);
    }

    sprintf(outfile, "%s.dec", argv[1]);
    decrypt_file(argv[1], outfile);
#endif

    return 0;
}
