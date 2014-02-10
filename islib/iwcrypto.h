#ifndef IWCRYPTO_H
#define IWCRYPTO_H

typedef struct _IW_EXCRYPTO {
    char *buff;
    int  bufflen;
    int  result;
    char *errmsg;
} IW_EXCRYPTO;

IW_EXCRYPTO *IW_ExEncrypto( char *buff, int bufflen );
IW_EXCRYPTO *IW_ExDecrypto( char *buff, int bufflen );

IW_EXCRYPTO *IW_ExCPTCreateCrypto( char *buff, int bufflen,
                                   int result, char *errmsg );
int IW_ExCPTReleaseCrypto( IW_EXCRYPTO *excrypto );

#endif /* #ifndef IWCRYPTO_H */
