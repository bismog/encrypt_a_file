#ifndef __BASE64_H__
#define __BASE64_H__

enum {BASE64_OK = 0, BASE64_INVALID};

#define BASE64_ENCODE_OUT_SIZE(s)   (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s)   (((s)) / 4 * 3)

int
base64_encode(const unsigned char *in, unsigned int inlen, char *out);

int
base64_decode(const char *in, unsigned int inlen, unsigned char *out);


char *base64(const void *input, int length, char *out);

void *decodeBase64(char *inputBase64, void *retBuf, int *retBufLen);

#endif /* __BASE64_H__ */
