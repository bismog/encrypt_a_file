#include <stdio.h>
#include <string.h>
#include <time.h>

#define VSEC_FILE_NAME_MAX 540

int append_log(char *line) {
    char log_file[VSEC_FILE_NAME_MAX] = {0};
    int idx = 0;

    idx = sprintf(log_file, "%s", "/tmp/log/xxx.log");
    FILE *fp = fopen(log_file, "a+");
    if (fp == NULL)
    {
        return 1;
    }

    fwrite(line, 1, strlen(line)+1, fp);
    fclose(fp);
    return 0;
}


int main() {
    time_t tt = time(NULL);
    char line[1024] = {0};

    struct tm gmttm;
    struct tm *gmt;
    gmtime_r(&tt, &gmttm);
    gmt = &gmttm;

    sprintf(line, "%d-%02d-%02d %02d:%02d:%02d\txxxxxxxxxxxxxxxxxxxxxxxxxx\n", 
            gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday, gmt->tm_hour, 
            gmt->tm_min, gmt->tm_sec);
    if (0 != append_log(line)) {
        return 1;
    }
    return 0;
}

