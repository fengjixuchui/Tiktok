#ifndef _YEMD5_H
#define _YEMD5_H

typedef struct{
    uint count[2];
    uint state[4];
    uchar buffer[64];
} md5_ctx_s;

void yemd5_init(md5_ctx_s *context);
void yemd5_update(md5_ctx_s *context, uchar *data, uint size);
void yemd5_final(md5_ctx_s *context, uchar digest[16]);

#endif // _YEMD5_H