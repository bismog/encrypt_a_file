#include <iostream>
#include <stdio.h>
#include <string.h>
#include <malloc.h>


#define REPLACE_FILE(old, new) rename((old), (new))
#define FILE_NAME_LEN   (512+1)
#define KEY_LEN   4096

static char pubkey_buf[KEY_LEN];

/*
 * The reversion of following script:
 *     with open(pubkey, 'wb') as f:
 *             f.write(key.publickey().exportKey('PEM').decode('utf-8'))
 *                     f.close()
 *                     */

/*-------------------------------------------------------------------------*/
/**
 * save_json_file
 *   @brief    save public key to file
 *   @param    0 if success, -1 if error.
 *      */
/*--------------------------------------------------------------------------*/

int save_pubkey(char* data)
{
    int   ret          = -1;
    unsigned int   len = 0;
    FILE* fd           = NULL;
    char* pubkey_path_bak = NULL;
    // const char*  pubkey_path = get_file_path(F_PUB_KEY);
    char pubkey_path[FILE_NAME_LEN];
    // const char* pubkey_path = "./id_rsa.xxxxxx";
    
    snprintf(pubkey_path, FILE_NAME_LEN, "%s", "./id_rsa.xxxxxx");
    len = strlen(pubkey_path)+5;
    pubkey_path_bak = (char*)malloc(len);
    snprintf(pubkey_path_bak, len, "%s.tmp", pubkey_path); 
    fd = fopen(pubkey_path_bak, "wb");
    if (NULL == fd){
        free(pubkey_path_bak);
        return -1;
    }

    if (fwrite(data, 1, strlen(data), fd) <= 0){
        fclose(fd);
        ret = -1;
    } else {
        fclose(fd);
        ret = REPLACE_FILE(pubkey_path_bak, pubkey_path);
    }
    remove(pubkey_path_bak);
    free(pubkey_path_bak);
    return ret;
}

/*-------------------------------------------------------------------------*/
/**
 * parse_json_file
 *   @brief    load public key from file
 *   @param    0 if success, -1 if error.
 *      */
/*--------------------------------------------------------------------------*/

char* load_pubkey()
{
    FILE*  fd   = NULL;
    long   len  = 0;
    // const char*  pubkey_path = get_file_path(F_PUB_KEY);
    // const char* pubkey_path = "./id_rsa.pub";
    char pubkey_path[FILE_NAME_LEN];

    snprintf(pubkey_path, FILE_NAME_LEN, "%s", "./id_rsa.pub");
    fd = fopen(pubkey_path, "rb");
    if (NULL == fd){
        //LOG_INFO("Not find: %s.", pubkey_path);
        return NULL;
    }

    fseek(fd, 0, SEEK_END);
    len = ftell(fd);
    if (0 == len){
        //LOG_INFO("file size is zero: %s", pubkey_path);
        fclose(fd);
        return NULL;
    }
    fseek(fd, 0, SEEK_SET);

    if (fread(pubkey_buf, 1, len, fd) <= 0){
        fclose(fd);
        return NULL;
    }
    fclose(fd);
    return pubkey_buf;
}


int main() {
    char* pubkey = NULL;
    int ret = 0;
    
    pubkey = load_pubkey();
    if (pubkey == NULL){
        printf("load public key failed!\n");
        return -1;
    }
    ret = save_pubkey(pubkey);
    if (ret == -1) {
        printf("save public key failed!\n");
        return -1;
    }
    printf("%s", pubkey);
    return 0;
}
