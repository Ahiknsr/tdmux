#include <assert.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

void init_ssl();
SSL_CTX* get_ssl_ctx();