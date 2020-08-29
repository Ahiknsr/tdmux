#include <structs.h>
#include <sslProcessor.h>
#include <configManager.h>

int preProcess(Request *request);
int parseConnectRequest(Request *request);
int parseHostHeader(Request *request);
int parseSSHRequest(Request *request);
int parseSSLRequest(Request *request);