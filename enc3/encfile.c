
#include "encrypt.h"


int main() {
    char infile[256] = "./plain_file";
    char outfile[256] = "./crypt_file";

    encrypt_file(infile, outfile);
    return 0;
}
