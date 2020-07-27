#include <structs.h>

int preProcess(Request *request, uv_loop_t *loop);
int parseHostHeader(Request *request);
int parseConnectRequest(Request *request, uv_loop_t *loop);
int parseSSHRequest(Request *request);
