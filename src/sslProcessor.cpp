#include <sslProcessor.h>

SSL_CTX *ctx{nullptr};

/*
copy n bytes from src to dest
ordering of bytes copied depends on endianness
*/
void copyBytes(uint8_t *dest, uint8_t *src, size_t n)
{
    auto isLittleEndian =[](){
        uint16_t temp = 1;
        return (*(uint8_t*)(&temp)) == 1;
    };

    if (n==0)
        return;
    
    if (isLittleEndian())
    {
        dest = dest+n-1;
        while (n>0)
        {
            *dest=*src;
            dest--;
            src++;
            n--;
        }
    }
    else
    {
        memcpy(dest, src, n);
    }
}

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

enum SSL_STATUS getSSLStatus(SSL* ssl, int n)
{
  switch (SSL_get_error(ssl, n))
  {
    case SSL_ERROR_NONE:
      return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
      return SSLSTATUS_FAIL;
  }
}

void requestInitSSL(struct Request *request)
{
  request->crbio = BIO_new(BIO_s_mem());
  request->cwbio = BIO_new(BIO_s_mem());

  request->clientssl = SSL_new(get_ssl_ctx());

  SSL_set_accept_state(request->clientssl);
  SSL_set_bio(request->clientssl, request->crbio, request->cwbio);

  request->srbio = BIO_new(BIO_s_mem());
  request->swbio = BIO_new(BIO_s_mem());

  request->serverssl = SSL_new(get_ssl_ctx());

  SSL_set_accept_state(request->serverssl);
  SSL_set_bio(request->serverssl, request->srbio, request->swbio);
}

enum SSL_STATUS CompleteHandshakeWithServer(Request *request)
{
  char buf[1000];
  enum SSL_STATUS status;

  int n = SSL_do_handshake(request->serverssl);
  status = getSSLStatus(request->serverssl, n);

  if (status == SSLSTATUS_WANT_IO)
  {
    do 
    {
      n = BIO_read(request->swbio, buf, sizeof(buf));
      if (n > 0)
        sendBytesToServer(buf, n, request);
      // fix assert messages?
      else if (!DELETE_REQUEST_IF_FAILED("BIO_write failed",\
          BIO_should_retry(request->swbio), request))
          return SSLSTATUS_FAIL;
    } while (n>0);
  }
  return status;
}

std::string parseHostNameFromExtensions(const std::vector<char> buffer, uint16_t startIndex)
{
    uint16_t expectedExtensionLength{0};
    copyBytes((uint8_t*)&expectedExtensionLength, (uint8_t*)&buffer[startIndex], 2);

    assert(expectedExtensionLength == (buffer.size() - startIndex -2));

    uint16_t extensionId{0};
    uint16_t extensionLen{0};
    uint8_t firstEntryId{0};
    uint16_t hostNameLen{0};

    uint16_t currIndex = startIndex+2;
    uint16_t SNIExtensionId = 0x0000;
    uint8_t hostNameId = 0x00;

    while (currIndex < startIndex + 2 + expectedExtensionLength)
    {
        copyBytes((uint8_t*)&extensionId, (uint8_t*)&buffer[currIndex], 2);
        copyBytes((uint8_t*)&extensionLen, (uint8_t*)&buffer[currIndex+2], 2);
        if (SNIExtensionId == extensionId)
        {
            copyBytes((uint8_t*)&firstEntryId, (uint8_t*)&buffer[currIndex+6], 1);
            assert(firstEntryId == hostNameId);
            copyBytes((uint8_t*)&hostNameLen, (uint8_t*)&buffer[currIndex+7], 2);
            std::string hostName(&buffer[currIndex+9], &buffer[currIndex+9+hostNameLen]);
            logmsg("hostname %s\n", hostName.c_str());
            return hostName;
        }
        currIndex = currIndex + 4 + extensionLen;
    }
    return {};
}

/*
decrypt encrypted content in crbuffer and write decrypted content to swbuffer
returns the number of bytes leftover after decryption
if we encounter failure during decryption negative value is returned
*/
int onSSLClientRead(Request *request)
{
    char buf[500], *src; /* used for copying bytes out of SSL/BIO */
    enum SSL_STATUS status;
    int originalLen, currLen,n;
    
    originalLen = request->crbuffer.size();
    if (!originalLen)
      return 0;
    src = &request->crbuffer[0];
    currLen = originalLen;

    while (currLen > 0) 
    {
        n = BIO_write(request->crbio, src, currLen);

        if (!DELETE_REQUEST_IF_FAILED("BIO_write failed", (n>0), request))
        {
            return -1;
        }

        src += n;
        currLen -= n;

        if (!SSL_is_init_finished(request->clientssl)) 
        {
            n = SSL_accept(request->clientssl);
            status = getSSLStatus(request->clientssl, n);

            /* Did SSL request to write bytes? */
            if (status == SSLSTATUS_WANT_IO)
            {
                do 
                {
                    n = BIO_read(request->cwbio, buf, sizeof(buf));
                    if (n > 0)
                        sendBytesToClient(buf, n, request);
                    else if (!DELETE_REQUEST_IF_FAILED("BIO_write failed",\
                        BIO_should_retry(request->cwbio), request))
                        return -1;
                } while (n>0);
            }

            if (status == SSLSTATUS_FAIL)
                return -1;

            if (!SSL_is_init_finished(request->clientssl))
            { 
              request->crbuffer = std::move(std::vector<char>(
                                    request->crbuffer.begin() + originalLen - currLen,
                                    request->crbuffer.end()));
              return currLen;
            }
        }

        /* The encrypted data is now in the input bio so now we can perform actual
            * read of unencrypted data. */
        do 
        {
            n = SSL_read(request->clientssl, buf, sizeof(buf));
            if (n > 0)
            {
                auto swbufferLen = request->swbuffer.size();
                request->swbuffer.resize(swbufferLen+n);
                memcpy(&(request->swbuffer[0])+swbufferLen, buf, n);
            }
        } while (n > 0);

        status = getSSLStatus(request->clientssl, n);

        /* Did SSL request to write bytes? This can happen if peer has requested SSL
            * renegotiation. */
        if (status == SSLSTATUS_WANT_IO)
        {
            do 
            {
                n = BIO_read(request->cwbio, buf, sizeof(buf));
                if (n > 0)
                    sendBytesToClient(buf, n, request);
                else if (!DELETE_REQUEST_IF_FAILED("BIO_write failed",\
                    BIO_should_retry(request->cwbio), request))
                    return -1;
            } while (n>0);
        }

        if (status == SSLSTATUS_FAIL)
            return -1;
            // delete request
    }
    request->crbuffer = std::move(std::vector<char>(
                          request->crbuffer.begin() + originalLen - currLen,
                          request->crbuffer.end()));
    return currLen;  
}

/*
encrypts the content in cwbuffer and sends it to client
returns the number of bytes leftover
returns negative value if encryption fails
*/
int WriteToClient(Request *request)
{
    char buf[500], *src; /* used for copying bytes out of SSL/BIO */
    enum SSL_STATUS status;
    int currLen,originalLen;

    originalLen = request->cwbuffer.size();
    if(!originalLen)
      return originalLen;

    currLen = originalLen;
    src = &request->cwbuffer[0];
    if (!SSL_is_init_finished(request->clientssl))
      return currLen;

    while (currLen>0)
    {
        int n = SSL_write(request->clientssl, src, currLen);
        status = getSSLStatus(request->clientssl, n);

        if (n>0) 
        {
            currLen-=n;
            src+=n;

            do 
            {
                n = BIO_read(request->cwbio, buf, sizeof(buf));
                if (n > 0)
                    sendBytesToClient(buf, n, request);
                else if (!DELETE_REQUEST_IF_FAILED("BIO_write failed",\
                    BIO_should_retry(request->cwbio), request))
                    return -1;
            } while (n>0);
        }

        if (status == SSLSTATUS_FAIL)
          return -1;

        if (n==0)
            break;
    }
    request->cwbuffer = std::move(std::vector<char>(
                          request->cwbuffer.begin() + originalLen - currLen,
                          request->cwbuffer.end()));
    return currLen;
}

/*
decrypt encrypted content in srbuffer and write decrypted content to cwbuffer
returns the number of bytes leftover after decryption
if we encounter failure during decryption negative value is returned
*/
int onSSLServerRead(Request *request)
{
  char buf[1000], *src;
  enum SSL_STATUS status;
  int n, currLen, originalLen;

  originalLen = request->srbuffer.size();
  if (!originalLen)
    return originalLen;
  currLen = originalLen;
  src = &request->srbuffer[0];

  while (currLen > 0) 
  {
    n = BIO_write(request->srbio, src, currLen);

    if (!DELETE_REQUEST_IF_FAILED("BIO_write failed", (n>0), request))
    {
        return -1;
    }

    src += n;
    currLen -= n;

    if (!SSL_is_init_finished(request->serverssl)) 
    {
      if (CompleteHandshakeWithServer(request) == SSLSTATUS_FAIL)
      {
        // use the macro
        logmsg("server handshake failed\n");
        deleteRequest(request);
        return -1;
      }
      if (!SSL_is_init_finished(request->serverssl))
      {
        request->srbuffer = std::move(std::vector<char>(
                              request->srbuffer.begin() + originalLen - currLen,
                              request->srbuffer.end()));
        return currLen;
      }
    }

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */

    do 
    {
      n = SSL_read(request->serverssl, buf, sizeof(buf));
      if (n > 0)
      {
        auto cwbufferLen = request->cwbuffer.size();
        request->cwbuffer.resize(cwbufferLen+n);
        memcpy(&(request->cwbuffer[0])+cwbufferLen, buf, n);
      }
    } while (n > 0);

    status = getSSLStatus(request->serverssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */
    if (status == SSLSTATUS_WANT_IO)
    {
      do 
      {
        n = BIO_read(request->swbio, buf, sizeof(buf));
        if (n > 0)
          sendBytesToServer(buf, n, request);
        else if (!BIO_should_retry(request->swbio))
        {
          deleteRequest(request);
          return -1;
        }
      } while (n>0);
    }

    if (status == SSLSTATUS_FAIL)
      return -1;
  }
  request->srbuffer = std::move(std::vector<char>(
                        request->srbuffer.begin() + originalLen - currLen,
                        request->srbuffer.end()));
  return currLen;
}

/*
encrypts the content in swbuffer and sends it to server
returns the number of bytes leftover
returns negative value if encryption fails
*/
int WriteToServer(Request *request)
{
  char buf[500], *src; /* used for copying bytes out of SSL/BIO */
  enum SSL_STATUS status;
  int currLen,originalLen;

  originalLen = request->swbuffer.size();
  if(!originalLen)
    return originalLen;

  currLen = originalLen;
  src = &request->swbuffer[0];

  if (!SSL_is_init_finished(request->serverssl)) 
  {
    logmsg("WriteToServer init not complete");
    if (CompleteHandshakeWithServer(request) == SSLSTATUS_FAIL)
    {
      // use the macro
      logmsg("server handshake failed\n");
      deleteRequest(request);
      return -1;
    }
    if (!SSL_is_init_finished(request->serverssl))
    {
      logmsg("WriteToServer init still not complete");
      return currLen;
    }
  }
  while (currLen>0) 
  {
    int n = SSL_write(request->serverssl, src, currLen);
    status = getSSLStatus(request->serverssl, n);

    if (n>0) 
    {
      src+=n;
      currLen-=n;

      /* take the output of the SSL object and queue it for socket write */
      do {
        n = BIO_read(request->swbio, buf, sizeof(buf));
        if (n > 0)
        {
          sendBytesToServer(buf, n, request);
        }
        else if (!BIO_should_retry(request->swbio))
        {
          deleteRequest(request);
          return -1;
        }
      } while (n>0);
    }

    if (status == SSLSTATUS_FAIL)
      return -1;

    if (n==0)
      break;
  }
  request->swbuffer = std::move(std::vector<char>(
                      request->swbuffer.begin() + originalLen - currLen,
                      request->swbuffer.end()));
  return currLen;
}

void sendBytesToClient(char *buf, int len, Request *request)
{
  write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
  write_req->buf = uv_buf_init((char*) malloc(len), len);
  memcpy(write_req->buf.base, buf, len);

  uv_write((uv_write_t*)write_req, (uv_stream_t*)request->client, 
      &write_req->buf, 1 /*nbufs*/, on_write_end);
}

void sendBytesToServer(char *buf, int len, Request *request)
{
  logmsg("sending %d bytes to server\n", len);
  write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
  write_req->buf = uv_buf_init((char*) malloc(len), len);
  memcpy(write_req->buf.base, buf, len);

  uv_write((uv_write_t*)write_req, (uv_stream_t*)request->server, 
      &write_req->buf, 1 /*nbufs*/, on_write_end);
}

int processCondition(const char *file, int lineno, const char *msg, int expr, Request *request)
{
    int temp = expr;
    if (!temp)
    {
        logmsg("assertion failure at %s:%d %s\n", file, lineno, msg);
        deleteRequest(request);
    }
    return temp;
}