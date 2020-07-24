#include <structs.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include <uv.h>

const std::string DEFAULT_PORT = "80";
const std::string HTTPS_PORT = "443";
const std::string HOSTKEY = "host: ";
const std::string HEADERDELIMITER = "\r\n";
const std::string COLON = ":";
const std::string CONNECT = "CONNECT";
const std::string SPACE = " ";
const std::string CONNECT_RESPONSE = "HTTP/1.1 200 Connection established\r\n\r\n";

void free_write_req(uv_write_t *req);
void on_write_end(uv_write_t *req, int status);

int parseHostHeader(Request *request);
int parseConnectRequest(Request *request, uv_loop_t *loop);

int preProcess(Request *request, uv_loop_t *loop)
{
    if (parseConnectRequest(request, loop))
        return true;
    if (parseHostHeader(request))
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

    request->serverPort = HTTPS_PORT;

    auto hostAndPort = buffer_s.substr(CONNECT.size()+1,headerDelimiterIndex-CONNECT.size());
    auto spaceIndex = hostAndPort.find(SPACE);
    hostAndPort = hostAndPort.substr(0, spaceIndex);
    printf("temp is %s\n", hostAndPort.c_str());
    auto colonIndex = hostAndPort.find(COLON);
    if (colonIndex != std::string::npos)
    {
        auto port = hostAndPort.substr(colonIndex+1, hostAndPort.size()-colonIndex);
        auto host = hostAndPort.substr(0, colonIndex);
        request->serverName = host;
        request->serverPort = port;

        printf("host is %s port is %s\n", host.c_str(), port.c_str());

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
    // todo: just lower case 'H','O','S','T'
    std::transform(buffer_s.begin(), buffer_s.end(), buffer_s.begin(), ::tolower);
    // logmsg("parsing content:\n");
    // logmsg("%s\n", buffer_s.c_str());

    auto hostIndex = buffer_s.find(HOSTKEY);
    if (hostIndex == std::string::npos)
        return 0;

    auto hostIndexEnd = buffer_s.find(HEADERDELIMITER, hostIndex + HOSTKEY.size());
    if (hostIndexEnd == std::string::npos)
        return 0;

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