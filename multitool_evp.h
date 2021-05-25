#ifndef MULTITOOL_EVP_H
#define MULTITOOL_EVP_H
#include <multitool_c_util.h>

int keygen_evp(keyIVpair *keyParams);
int crypt_evp(int mode, char filePath[]);


#endif // MULTITOOL_EVP_H
