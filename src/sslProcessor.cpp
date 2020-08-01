#include <sslProcessor.h>

SSL_CTX *ctx{nullptr};

void init_ssl() 
{
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* create the SSL server context */
  ctx = SSL_CTX_new(SSLv23_server_method());
  if (!ctx)
    assert(false);
    // int_error("SSL_CTX_new()");

  /* Load certificate and private key files, and check consistency  */
  int err;
  err = SSL_CTX_use_certificate_file(ctx, "cert.pem",  SSL_FILETYPE_PEM);
  if (err != 1)
    assert(false);
    // int_error("SSL_CTX_use_certificate_file failed");
  else
    printf("certificate file loaded ok\n");

  /* Indicate the key file to be used */
  err = SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);
  if (err != 1)
    assert(false);
    // int_error("SSL_CTX_use_PrivateKey_file failed");
  else
    printf("private-key file loaded ok\n");

  if (SSL_CTX_check_private_key(ctx) != 1)
    assert(false);
    // int_error("SSL_CTX_check_private_key failed");
  else
    printf("private key verified ok\n");

  SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
}

SSL_CTX* get_ssl_ctx()
{
    if (ctx == nullptr)
        init_ssl();
    return ctx;
}