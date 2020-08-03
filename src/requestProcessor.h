#include <structs.h>
#include <sslProcessor.h>
#include <configManager.h>

int preProcess(Request *request);
int parseHostHeader(Request *request);
int parseConnectRequest(Request *request);
int parseSSHRequest(Request *request);
int parseSSLRequest(Request *request);
int onEncryptedClientRead(Request *request, char *src, size_t len);
int encryptAndWriteToClient(Request *request, char *src, size_t len);