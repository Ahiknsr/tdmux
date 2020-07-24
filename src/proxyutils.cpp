#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <uv.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <structs.h>

const std::string HOSTKEY = "host: ";
const std::string headerDelimiter = "\r\n";
const std::string COLON = ":";
const std::string DEFAULT_PORT = "80";

void parseHost(const std::vector<char>& buffer, std::string& host, std::string& port)
{
    port = DEFAULT_PORT;
    host.clear();
    if (buffer.size() <= HOSTKEY.size())
        return;
    
    std::string buffer_s(&buffer[0], &buffer[buffer.size()-1]);
    std::transform(buffer_s.begin(), buffer_s.end(), buffer_s.begin(), ::tolower);
    
    auto hostIndex = buffer_s.find(HOSTKEY);
    //std::cout<<buffer_s<<"\n";
    if (hostIndex == std::string::npos)
        return;

    auto hostIndexEnd = buffer_s.find(headerDelimiter, hostIndex + HOSTKEY.size());
    if (hostIndexEnd == std::string::npos)
        return;

    host = buffer_s.substr(hostIndex+HOSTKEY.size(), 
                           hostIndexEnd-hostIndex-HOSTKEY.size());
    //std::cout<<host<<"\n";
    auto colonIndex = host.find(COLON);
    if (colonIndex == std::string::npos)
        return;
    port = host.substr(colonIndex+1, host.size()-colonIndex-1);
    host.resize(colonIndex);
}

void logmsg(const char* format, ...)
{
    time_t now_tm;
    char *now;

    now_tm = time(NULL);
    now = ctime(&now_tm);
    UNUSEDPARAM(now);

    //fprintf(stdout, "[%d] [%.22s] ", getpid(), now);
    va_list ap;
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
    fflush(stdout);
}

void fillClientDebugInfo(Request *request)
{
    uv_tcp_t *client = request->client;
	struct sockaddr_storage storage;
    int len, res;
    char ip[NI_MAXHOST], port[NI_MAXSERV];

	memset(&storage, 0, sizeof(storage));
	
    len = sizeof(storage);
    res = uv_tcp_getpeername(client, (struct sockaddr*)&storage, &len);
    if (res < 0)
    {
        logmsg("uv_tcp_getpeername failed\n");
        return;
    }

    res = getnameinfo((struct sockaddr*)&storage, len, ip, 
                NI_MAXHOST, port, NI_MAXSERV, 0);
    if (res != 0) 
    {
        logmsg("getnameinfo failed\n");
        return;
    }
    request->clientIp = ip;
    request->clientPort = port;
}

std::string getClientInfo(const Request *request)
{
    return request->clientIp + ":" + request->clientPort;
}

std::string getServerInfo(const Request *request)
{
    return (request->serverIp.size() > 0  ?  
                request->serverIp :
                request->serverName) + 
            ":" +
            request->serverPort;
}

std::string getRequestInfo(const Request *request)
{
    return getClientInfo(request) + "::" + getServerInfo(request);
}