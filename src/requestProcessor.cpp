#include <assert.h>

#include <algorithm>
#include <cstring>

#include <structs.h>
#include <proxyUtils.h>
#include <requestProcessor.h>

extern ConfigManager *config;

const std::string DEFAULT_PORT = "80";
const std::string HTTPS_PORT = "443";
const std::string HOSTKEY = "HOST: ";
const std::string HEADERDELIMITER = "\r\n";
const std::string COLON = ":";
const std::string CONNECT = "CONNECT";
const std::string SPACE = " ";
const std::string CONNECT_RESPONSE = "HTTP/1.1 200 Connection established\r\n\r\n";
const std::string SSH_PREFIX = "SSH"; // needs to be more specific

int preProcess(Request *request)
{
    assert(request->protocol == Protocol::UNKNOWN);
    if (parseConnectRequest(request))
        return true;
    if (parseHostHeader(request))
        return true;
    if (parseSSHRequest(request))
        return true;
    if (parseSSLRequest(request))
        return true;
    return false;
}

int parseConnectRequest(Request *request)
{
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
    if (config->isEnabled(config->MITMHTTPCONNECT))
    {
        logmsg("performing mitm\n");
        request->protocol = Protocol::UNKNOWN;
        return false;
    }
    request->protocol = Protocol::HTTPS;
    return true;
}

int parseHostHeader(Request *request)
{
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
    request->serverPort = DEFAULT_PORT;
    request->serverName.clear();
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
    
    copyBytes((uint8_t*)&messageLength, (uint8_t*)&buffer[3], 2);

    uint16_t expectedBufferSize = messageLength + 5;

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

    request->protocol = Protocol::TLS;

    uint16_t sessionIDLenIndex = 5 /*Record header*/ + 4 /*Handshake header*/ 
                                + 2 /*client version*/ + 32 /*client random*/;
    
    uint16_t sessionIDLength{0};
    copyBytes((uint8_t*)&sessionIDLength, (uint8_t*)(&buffer[sessionIDLenIndex]), 1);

    uint16_t cipherSuitesLenIndex = sessionIDLenIndex + sessionIDLength + 1;
    uint16_t cipherSuitesLength{0};
    copyBytes((uint8_t*)&cipherSuitesLength, (uint8_t*)(&buffer[cipherSuitesLenIndex]), 2);

    uint8_t compressionMethodLenIndex = cipherSuitesLenIndex + cipherSuitesLength + 2;
    uint8_t compressionMethodLength{0};
    copyBytes(&compressionMethodLength,(uint8_t*)(&buffer[compressionMethodLenIndex]), 1);

    uint8_t extensionsLenIndex = compressionMethodLenIndex + compressionMethodLength + 1;
    uint16_t extensionsLength{0};
    copyBytes((uint8_t*)&extensionsLength,(uint8_t*)(&buffer[extensionsLenIndex]), 2);

    // will be already filled in
    // request->serverName = parseHostNameFromExtensions(buffer, extensionsLenIndex);
    // request->serverPort = "7878";
    requestInitSSL(request);
    return true;
}

/*
process the encrypted data sent by client.
This method is synchronous and doesn't block
*/
int onEncryptedClientRead(Request *request, char* src, size_t len)
{
    char buf[500]; /* used for copying bytes out of SSL/BIO */
    enum SSL_STATUS status;
    int n;

    while (len > 0) 
    {
        n = BIO_write(request->crbio, src, len);

        if (!DELETE_REQUEST_IF_FAILED("BIO_write failed", (n>0), request))
        {
            return -1;
        }

        src += n;
        len -= n;

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
                return len;
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
    return len;
}

int encryptAndWriteToClient(Request *request, char *src, size_t len)
{
    if (!SSL_is_init_finished(request->clientssl))
        return len;

    char buf[500]; /* used for copying bytes out of SSL/BIO */
    enum SSL_STATUS status;

    while (len>0)
    {
        int n = SSL_write(request->clientssl, src, len);
        status = getSSLStatus(request->clientssl, n);

        if (n>0) 
        {
            len-=n;
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
    return len;
}