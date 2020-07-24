#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <uv.h>

#include <string>

#include <structs.h>

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

void free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void on_write_end(uv_write_t *req, int status) 
{
  if (status == -1) 
  {
    logmsg("error on_write_end");
  }
  free_write_req(req);
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