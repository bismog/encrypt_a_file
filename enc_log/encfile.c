
#include "encrypt.h"


int main(int argc, char *argv[]) {
    char outfile[512] = {0};

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Data File>\n", argv[0]);
        fprintf(stderr, "       This will generate encrypt file \"xxx.enc\".\n");
        exit(1);
    }

    sprintf(outfile, "%s.enc", argv[1]);
    encrypt_file(argv[1], outfile);
    // decrypt_file(outfile, outfile2);
    return 0;
}
