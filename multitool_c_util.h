#ifndef MULTITOOL_C_UTIL_H
#define MULTITOOL_C_UTIL_H

typedef struct keyIVpair
{
    unsigned char *key;
    unsigned char *iv;
}keyIVpair;

typedef struct deriveStruct{
    unsigned char *salt;
    char *pass;
}deriveStruct;

void cleanup(keyIVpair * kp, deriveStruct * dp);

#endif // MULTITOOL_C_UTIL_H
