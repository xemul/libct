#ifndef __LIBCT_RPC_H__
#define __LIBCT_RPC_H__

struct _RpcResponce;
typedef struct _RpcResponce RpcResponce;

extern int do_send_resp(int sk, int err, RpcResponce *resp);
extern int send_resp(int sk, int err);

#endif
