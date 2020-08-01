#include <structs.h>
#include <sslProcessor.h>

int preProcess(Request *request, uv_loop_t *loop);
int parseHostHeader(Request *request);
int parseConnectRequest(Request *request, uv_loop_t *loop);
int parseSSHRequest(Request *request);
int parseSSLRequest(Request *request);
void request_init_client_ssl(struct Request *request);
void sendServerHello(Request* request);