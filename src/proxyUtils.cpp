#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <proxyUtils.h>

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

void deleteRequest(Request *request)
{
    if (request == nullptr)
        return;

    logmsg("destroying request %s\n", getRequestInfo(request).c_str());

    uv_tcp_t_r *client = (uv_tcp_t_r*)request->client;
    uv_tcp_t_r *server = (uv_tcp_t_r*)request->server;

    if (client)
    {
        if (request->clientssl)
        {
            free(request->clientssl);
            BIO_free(request->crbio);
            BIO_free(request->cwbio);
        }
        request->client = nullptr;
        client->request = nullptr;
        uv_close((uv_handle_t*)client, freeHandle);
    }
    if (server)
    {
        if (request->serverssl)
        {
            free(request->serverssl);
            BIO_free(request->srbio);
            BIO_free(request->swbio);
        }
        request->server = nullptr;
        server->request = nullptr;
        uv_close((uv_handle_t*)server, freeHandle);
    }
    if (request->logfile)
    {
        fclose(request->logfile);
    }
    delete request;
}

void free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void freeHandle(uv_handle_t *handle)
{
    uv_tcp_t_r *handle_r = (uv_tcp_t_r*)handle;
    delete handle_r;
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
    request->logfile =  fopen(getLogFileName(request).c_str(), "a");
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
                NI_MAXHOST, port, NI_MAXSERV, NI_NUMERICHOST);
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

std::string getLogFileName(const Request *request)
{
    // todo: replace tmpnam with mkstemp
    // filename should contain client ip
    UNUSEDPARAM(request);
    char logFileName[L_tmpnam];
    tmpnam(logFileName);
    std::string logFileName_S(logFileName);
    logmsg("log file is %s\n", logFileName_S.c_str());
    return logFileName_S;
}