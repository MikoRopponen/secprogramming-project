#include<multitool_c_util.h>
#include <stdlib.h>
#include <openssl/crypto.h>

void cleanup(keyIVpair * kp, deriveStruct * dp)
{
    OPENSSL_cleanse(dp->pass, sizeof(dp->pass));
    free(kp);
    free(dp);
}
