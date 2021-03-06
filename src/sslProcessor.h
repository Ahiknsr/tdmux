#include <assert.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <structs.h>
#include <proxyUtils.h>

#define DELETE_REQUEST_IF_FAILED(msg, expr, request)\
    processCondition(__FILE__, __LINE__, msg, expr, request)

int processCondition(const char *file, int lineno, const char *msg,
                        int expr, Request *request);

void copyBytes(uint8_t *dest, uint8_t *src, size_t n);

int onSSLClientRead(Request *request);
int writeToClient(Request *request);
int onSSLServerRead(Request *request);
int writeToServer(Request *request);

void sendBytesToClient(char *buf, int len, Request *request);
void sendBytesToServer(char *buf, int len, Request *request);

void initSSL();
void initRequestSSL(struct Request *request);
SSL_CTX* getServerSSLCtx();
SSL_CTX* getClientSSLCtx();
enum SSL_STATUS getSSLStatus(SSL *ssl, int n);
enum SSL_STATUS initSSLHandshakeWithServer(Request *request);
std::string parseHostNameFromExtensions(const std::vector<char> buffer, uint16_t startIndex);