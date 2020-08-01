#include <assert.h>

#include <algorithm>
#include <cstring>

#include <structs.h>
#include <proxyUtils.h>
#include <requestPreProcessor.h>

const std::string DEFAULT_PORT = "80";
const std::string HTTPS_PORT = "443";
const std::string HOSTKEY = "HOST: ";
const std::string HEADERDELIMITER = "\r\n";
const std::string COLON = ":";
const std::string CONNECT = "CONNECT";
const std::string SPACE = " ";
const std::string CONNECT_RESPONSE = "HTTP/1.1 200 Connection established\r\n\r\n";
const std::string SSH_PREFIX = "SSH"; // needs to be more specific

int preProcess(Request *request, uv_loop_t *loop)
{
    assert(request->protocol == Protocol::UNKNOWN);
    if (parseConnectRequest(request, loop))
        return true;
    if (parseHostHeader(request))
        return true;
    if (parseSSHRequest(request))
        return true;
    if (parseSSLRequest(request))
        return true;
    return false;
}

int parseConnectRequest(Request *request, uv_loop_t *loop)
{
    UNUSEDPARAM(loop);

    auto buffer = request->crbuffer;
    if (buffer.size() <= CONNECT.size())
        return 0;

    std::string buffer_s(&buffer[0], &buffer[buffer.size()-1]);

    auto connectIndex = buffer_s.find(CONNECT);
    if (connectIndex != 0)
        return 0;

    auto headerDelimiterIndex = buffer_s.find(HEADERDELIMITER);
    if (headerDelimiterIndex == std::string::npos)
        return 0;

    request->protocol = Protocol::HTTPS;
    request->serverPort = HTTPS_PORT;

    auto hostAndPort = buffer_s.substr(CONNECT.size()+1,headerDelimiterIndex-CONNECT.size());
    auto spaceIndex = hostAndPort.find(SPACE);
    hostAndPort = hostAndPort.substr(0, spaceIndex);
    auto colonIndex = hostAndPort.find(COLON);
    if (colonIndex != std::string::npos)
    {
        auto port = hostAndPort.substr(colonIndex+1, hostAndPort.size()-colonIndex);
        auto host = hostAndPort.substr(0, colonIndex);
        request->serverName = host;
        request->serverPort = port;

        logmsg("host is %s port is %s\n", host.c_str(), port.c_str());

        write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
        auto response_len = CONNECT_RESPONSE.size();
        write_req->buf = uv_buf_init((char*) malloc(response_len), response_len);
        memcpy(write_req->buf.base, CONNECT_RESPONSE.c_str(), response_len);

        request->crbuffer.resize(0);
        uv_write((uv_write_t*)write_req, (uv_stream_t*)request->client, &write_req->buf, 1 /*nbufs*/, on_write_end);
    }
    return true;
}

int parseHostHeader(Request *request)
{
    request->serverPort = DEFAULT_PORT;
    request->serverName.clear();

    auto buffer = request->crbuffer;
    if (buffer.size() <= HOSTKEY.size())
        return 0;
    
    std::string buffer_s(&buffer[0], &buffer[buffer.size()-1]);
    std::string buffer_s_temp(buffer_s);

    for(auto& c : buffer_s_temp)
    {
        // Header names are case-insensitive
        if(c == 'h' || c == 'o' || c == 's' || c == 't')
        {
            c = toupper(c);
        }
    }
    // logmsg("parsing content:\n");
    // logmsg("%s\n", buffer_s.c_str());

    auto hostIndex = buffer_s_temp.find(HOSTKEY);
    if (hostIndex == std::string::npos)
        return 0;

    auto hostIndexEnd = buffer_s_temp.find(HEADERDELIMITER, hostIndex + HOSTKEY.size());
    if (hostIndexEnd == std::string::npos)
        return 0;

    request->protocol = Protocol::HTTP;
    request->serverName = buffer_s.substr(hostIndex+HOSTKEY.size(), 
                           hostIndexEnd-hostIndex-HOSTKEY.size());
    // logmsg("\nhost is %s\n", request->serverName.c_str());
    auto colonIndex = request->serverName.find(COLON);
    if (colonIndex == std::string::npos)
        return true;
    request->serverPort = request->serverName.substr(colonIndex+1,
                             request->serverName.size()-colonIndex-1);
    request->serverName.resize(colonIndex);
    return true;
}

int parseSSHRequest(Request *request)
{
    auto buffer = request->crbuffer;
    if (buffer.size() <= SSH_PREFIX.size())
        return false;
    
    std::string buffer_s(&buffer[0], &buffer[buffer.size()-1]);
    for(size_t i=0;i<SSH_PREFIX.size();i++)
    {
        if(buffer_s[i] != SSH_PREFIX[i])
            return false;
    }

    request->protocol = Protocol::SSH;
    request->serverName = "localhost";
    request->serverPort = "22";
    return true;
}

/*
copy n bytes from src to dest
ordering of bytes copied depends on endianness
*/
void copybytes(uint8_t *dest, uint8_t *src, size_t n)
{
    auto isLittleEndian =[](){
        uint16_t temp = 1;
        return (*(uint8_t*)(&temp)) == 1;
    };

    if (n==0)
        return;
    
    bool copyInReverseOrder = isLittleEndian();
    if(copyInReverseOrder)
    {
        dest=dest+n-1;
        while(n>0)
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

// zero extension check?
std::string parseHostNameFromExtensions(const std::vector<char> buffer, uint16_t startIndex)
{
    uint16_t expectedExtensionLength{0};
    copybytes((uint8_t*)&expectedExtensionLength, (uint8_t*)&buffer[startIndex], 2);

    logmsg("expectedLen %d\n", expectedExtensionLength);
    assert(expectedExtensionLength == (buffer.size() - startIndex -2));

    uint16_t currIndex = startIndex+2;

    uint16_t extensionId{0};
    uint16_t extensionLen{0};
    uint8_t firstEntryId{0};
    uint16_t hostNameLen{0};

    uint16_t SNIExtensionId = 0x0000;
    uint8_t hostNameId = 0x00;
    while (currIndex < startIndex + 2 + expectedExtensionLength)
    {
        copybytes((uint8_t*)&extensionId, (uint8_t*)&buffer[currIndex], 2);
        copybytes((uint8_t*)&extensionLen, (uint8_t*)&buffer[currIndex+2], 2);
        logmsg("currIndex: %d\n", currIndex);
        logmsg("extn id: %02x %02x\n", (uint8_t)buffer[currIndex], (uint8_t)buffer[currIndex+1]);
        logmsg("extn len: %02x %02x\n", (uint8_t)buffer[currIndex+2], (uint8_t)buffer[currIndex+3]);
        if (SNIExtensionId == extensionId)
        {
            copybytes((uint8_t*)&firstEntryId, (uint8_t*)&buffer[currIndex+6], 1);
            assert(firstEntryId == hostNameId);
            copybytes((uint8_t*)&hostNameLen, (uint8_t*)&buffer[currIndex+7], 2);
            std::string hostName(&buffer[currIndex+9], &buffer[currIndex+9+hostNameLen]);
            logmsg("hostname %s\n", hostName.c_str());
            return hostName;
        }
        currIndex = currIndex + 4 + extensionLen;
    }
    return {};
}

/*
parse the clientHello, SNI extension needed
look at https://tls.ulfheim.net/ for reference
*/
int parseSSLRequest(Request *request)
{
    auto buffer = request->crbuffer;

    // need at-least 3 bytes
    if (buffer.size() < 3)
        return false;
    
    const uint8_t handshake_and_SSL_version[] = {0x16, 0x3, 0x1};
    int cmp_result;

    cmp_result = memcmp(&buffer[0], handshake_and_SSL_version, sizeof(handshake_and_SSL_version));

    if (cmp_result != 0)
        return false;

    uint16_t messageLength{0};
    
    copybytes((uint8_t*)&messageLength, (uint8_t*)&buffer[3], 2);

    uint16_t expectedBufferSize = messageLength + 5;
    logmsg("messageLength %d buffer %d\n", messageLength, buffer.size());

    if (buffer.size() > expectedBufferSize)
    {
        // not a SSL request
        return false;
    }
    if (buffer.size() < expectedBufferSize)
    {
        // didn't receive the complete clientHello
        return false;
    }

    uint16_t sessionIDLenIndex = 5 /*Record header*/ + 4 /*Handshake header*/ 
                                + 2 /*client version*/ + 32 /*client random*/;
    
    uint16_t sessionIDLength{0};
    copybytes((uint8_t*)&sessionIDLength, (uint8_t*)(&buffer[sessionIDLenIndex]), 1);
    logmsg("sessionIDLenIndex %d sessionId length %d\n", sessionIDLenIndex, sessionIDLength);

    for(uint16_t i=0;i<sessionIDLength;i++)
    {
        logmsg("%02x ", (uint8_t)buffer[sessionIDLenIndex+1+i]);
    }
    logmsg("\n");

    uint16_t cipherSuitesLenIndex = sessionIDLenIndex + sessionIDLength + 1;
    uint16_t cipherSuitesLength{0};
    copybytes((uint8_t*)&cipherSuitesLength, (uint8_t*)(&buffer[cipherSuitesLenIndex]), 2);
    logmsg("cipherSuitesLenIndex %d cipherSuitesLength %d\n", cipherSuitesLenIndex, cipherSuitesLength);

    for(uint16_t i=0;i<cipherSuitesLength;i+=2)
    {
        logmsg("%02x %02x ", (uint8_t)buffer[cipherSuitesLenIndex+2+i], 
                            (uint8_t)buffer[cipherSuitesLenIndex+3+i]);
    }
    logmsg("\n");

    uint8_t compressionMethodLenIndex = cipherSuitesLenIndex + cipherSuitesLength + 2;
    uint8_t compressionMethodLength{0};
    copybytes(&compressionMethodLength,(uint8_t*)(&buffer[compressionMethodLenIndex]), 1);

    uint8_t extensionsLenIndex = compressionMethodLenIndex + compressionMethodLength + 1;
    uint16_t extensionsLength{0};
    copybytes((uint8_t*)&extensionsLength,(uint8_t*)(&buffer[extensionsLenIndex]), 2);

    logmsg("extLenIndex %d buf size %d\n", extensionsLenIndex, buffer.size());
    for(uint16_t i=extensionsLenIndex;i<buffer.size();i++)
    {
        logmsg("%02x ",(uint8_t)buffer[i]);
    }
    logmsg("\n");
    request->serverName = parseHostNameFromExtensions(buffer, extensionsLenIndex);
    request->serverPort = "7878";
    request_init_client_ssl(request);
    sendServerHello(request);
    return false;
}

void request_init_client_ssl(struct Request *request)
{
  request->crbio = BIO_new(BIO_s_mem());
  request->cwbio = BIO_new(BIO_s_mem());

  request->clientssl = SSL_new(get_ssl_ctx());

  SSL_set_accept_state(request->clientssl);
  SSL_set_bio(request->clientssl, request->crbio, request->cwbio);
}

enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};

static enum sslstatus get_sslstatus(SSL* ssl, int n)
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

void queue_encrypted_bytes(char *buf, int len, Request *request)
{
    write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
    write_req->buf = uv_buf_init((char*) malloc(len), len);
    memcpy(write_req->buf.base, buf, len);

    uv_write((uv_write_t*)write_req, (uv_stream_t*)request->client, 
        &write_req->buf, 1 /*nbufs*/, on_write_end);
}

void sendServerHello(Request* request)
{
    char buf[500]; /* used for copying bytes out of SSL/BIO */
    enum sslstatus status;
    int n;

    auto len = request->crbuffer.size();
    char *src = &request->crbuffer[0];

    while (len > 0) 
    {
    n = BIO_write(request->crbio, src, len);

    if (n<=0)
    exit(0);
    //   return -1; /* if BIO write fails, assume unrecoverable */

    src += n;
    len -= n;

    if (!SSL_is_init_finished(request->clientssl)) {
    n = SSL_accept(request->clientssl);
    status = get_sslstatus(request->clientssl, n);

    /* Did SSL request to write bytes? */
    if (status == SSLSTATUS_WANT_IO)
    do {
    n = BIO_read(request->cwbio, buf, sizeof(buf));
    if (n > 0)
    {
    queue_encrypted_bytes(buf, n, request);
    }
    else if (!BIO_should_retry(request->cwbio))
    exit(0);
    // return -1;
    } while (n>0);

    if (status == SSLSTATUS_FAIL)
    exit(0);
    // return -1;

    if (!SSL_is_init_finished(request->clientssl))
    exit(0);
    // return 0;
    }
    }
}