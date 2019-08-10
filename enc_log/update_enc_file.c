#include "encrypt.h"
#include <string.h>

int update_log(ENC_FILE *ef, char *line) {
    int d_len = 0;
    char *p = NULL;

    d_len = ef->len + strlen(line) + 1;
    p = realloc(ef->data, d_len);
    if (p == NULL) {
        return 1;
    }

    ef->offset = ef->len;
    ef->data = p;
    ef->len = d_len;
    memcpy(ef->data+ef->offset, line, strlen(line)+1);

    return 0;
}

int main(int argc, char *argv[]) {
    char line[1024] = {0};
	ENC_FILE *ef = NULL;
    time_t tt = time(NULL);
    struct tm gmttm;
    struct tm *gmt;
    gmtime_r(&tt, &gmttm);
    gmt = &gmttm;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Data File>\n", argv[0]);
        fprintf(stderr, "       This will update encrypt file <Data File>.\n");
        exit(1);
    }

    sprintf(line, "%d-%02d-%02d %02d:%02d:%02d\txxxxxxxxxxxxxxxxxxxxxxxxxx\n", 
            gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday, gmt->tm_hour, 
            gmt->tm_min, gmt->tm_sec);

    ef = dec_open(argv[1]);
    if (ef == NULL) {
        return 1;
    }

    update_log(ef, line);

    set_enc_data(argv[1], ef);

    if (ef) {
        if (ef->data) {
            free(ef->data);
        }
        free(ef);
    }

    return 0;
}
