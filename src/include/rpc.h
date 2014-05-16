#ifndef __LIBCT_RPC_H__
#define __LIBCT_RPC_H__

struct _RpcResponce;
typedef struct _RpcResponce RpcResponce;
struct _RpcRequest;
typedef struct _RpcRequest RpcRequest;

extern int do_send_resp(int sk, RpcRequest *req, int err, RpcResponce *resp);
extern int send_resp(int sk, RpcRequest *req, int err);

extern int recv_req(int sk, RpcRequest **req, int **fds, int *nr_fds);

#endif
