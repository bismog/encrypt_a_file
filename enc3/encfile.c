
#include "encrypt.h"


int main() {
    char infile[256] = "./plain_file";
    char outfile[256] = "./crypt_file";
    char outfile2[256] = "./decrypt_file";

    encrypt_file(infile, outfile);
    decrypt_file(outfile, outfile2);
    return 0;
}
