#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include <cassert>
#include <cstring>
#include <string>
#include <vector> 

#include <structs.h>

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

int preProcess(Request *request, uv_loop_t *loop);
void logmsg(const char* format, ...);
void fillClientDebugInfo(Request *request);
std::string getClientInfo(const Request *request);
std::string getServerInfo(const Request *request);
std::string getRequestInfo(const Request *request);

uv_loop_t *loop;

void free_write_req(uv_write_t *req);
void on_write_end(uv_write_t *req, int status);

void free_handle(uv_handle_t *handle)
{
    uv_tcp_t_r *handle_r = (uv_tcp_t_r*)handle;
    delete handle_r;
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
        request->client = nullptr;
        client->request = nullptr;
        uv_close((uv_handle_t*)client, free_handle);
    }
    if (server)
    {
        request->server = nullptr;
        server->request = nullptr;
        uv_close((uv_handle_t*)server, free_handle);
    }
    delete request;
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) 
{
    UNUSEDPARAM(handle);
    buf->base = (char*) malloc(suggested_size);
    buf->len = suggested_size;
}

void on_client_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    uv_tcp_t_r* client_r = (uv_tcp_t_r*)client;
    Request* request = client_r->request;

    logmsg("connection %s received data from client\n", getRequestInfo(request).c_str());
    
    if(nread < 0)
    {
        if (nread != UV_EOF)
        {
            logmsg("connection %s client read error %s\n", getRequestInfo(request).c_str(),
                                                           uv_err_name(nread));
        }
        else
        {
            logmsg("connection %s received EOF from client\n", getRequestInfo(request).c_str());
        }
        
        deleteRequest(request);
        return;
    }
    else
    {
        // write to server
        write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
        write_req->buf = uv_buf_init((char*) malloc(nread), nread);
        memcpy(write_req->buf.base, buf->base, nread);
        free(buf->base);

        uv_write((uv_write_t*)write_req, (uv_stream_t*)request->server, 
                    &write_req->buf, 1 /*nbufs*/, on_write_end);
    }
}

void on_server_read(uv_stream_t *server, ssize_t nread, const uv_buf_t *buf) 
{
    uv_tcp_t_r* server_r = (uv_tcp_t_r*)server;
    Request* request = server_r->request;

    logmsg("connection %s received data from server\n", getRequestInfo(request).c_str());

    if(nread < 0)
    {
        if (nread != UV_EOF)
        {
            logmsg("connection %s server read error %s\n", getRequestInfo(request).c_str(),
                                                           uv_err_name(nread));
        }
        else
        {
            logmsg("connection %s received EOF from server\n", getRequestInfo(request).c_str());
        }
        deleteRequest(request);
        return;
    }
    else
    {
        logmsg("server data is bytes %d %s\n", nread, buf->base);
        // write to client
        write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
        write_req->buf = uv_buf_init((char*) malloc(nread), nread);
        memcpy(write_req->buf.base, buf->base, nread);
        free(buf->base);

        uv_write((uv_write_t*)write_req, (uv_stream_t*)request->client, 
                    &write_req->buf, 1 /*nbufs*/, on_write_end);
    }
}

void on_server_connect(uv_connect_t *req, int status) 
{
    uv_connect_t_r *req_r = (uv_connect_t_r*)req;
    Request *request = req_r->request;
    uv_tcp_t_r *server = (uv_tcp_t_r*)request->server;
    delete req_r;

    if (status < 0) 
    {
        logmsg("error on_server_connect %s \n", uv_err_name(status));
        deleteRequest(request);
        return;
    }
    assert(status == 0);
    logmsg("client %s connected to server %s\n", getClientInfo(request).c_str(), 
                                                 getServerInfo(request).c_str());

    if (request->crbuffer.size() > 0)
    {
        write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
        auto client_r_buffer_len = request->crbuffer.size();
        write_req->buf = uv_buf_init((char*) malloc(client_r_buffer_len), client_r_buffer_len);
        memcpy(write_req->buf.base, &request->crbuffer[0], client_r_buffer_len);
        request->crbuffer.resize(0);

        uv_write((uv_write_t*)write_req, (uv_stream_t*)server, &write_req->buf, 1 /*nbufs*/, on_write_end);
    }
    uv_read_start((uv_stream_t*) request->client, alloc_buffer, on_client_read);
    uv_read_start((uv_stream_t*) request->server, alloc_buffer, on_server_read);
}


void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) 
{
    uv_getaddrinfo_t_r *resolver_r = (uv_getaddrinfo_t_r*)resolver;
    Request *request = resolver_r->request;
    if (status < 0) 
    {
        logmsg("getaddrinfo callback error %s\n", uv_err_name(status));
        deleteRequest(request);
    }
    else
    {
        char addr[17] = {'\0'};
        uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
        request->serverIp = addr;

        logmsg("server name %s resolved to %s\n", request->serverName.c_str(), request->serverIp.c_str());
        uv_connect_t_r *connect_req = new uv_connect_t_r();
        connect_req->request = request;

        uv_tcp_t_r *server = new uv_tcp_t_r();
        server->request = request;
        request->server = (uv_tcp_t*)server;

        uv_tcp_init(loop, (uv_tcp_t*)server);

        uv_tcp_connect((uv_connect_t*)connect_req, (uv_tcp_t*)server, 
                    (const struct sockaddr*) res->ai_addr, on_server_connect);   
    }
    delete resolver_r;
    uv_freeaddrinfo(res);
}

void on_client_init_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) 
{
    // stop reading while we process
    uv_read_stop(client);
    uv_tcp_t_r* client_r = (uv_tcp_t_r*)client;
    Request* request = client_r->request;
    if(nread < 0)
    {
        if (nread != UV_EOF)
            logmsg("Read error %s\n", uv_err_name(nread));
        deleteRequest(request);
        return;
    }
    else
    {
        auto curr_cr_buffer_len = request->crbuffer.size();
        logmsg("temp %d %d\n", curr_cr_buffer_len, curr_cr_buffer_len+nread);
        request->crbuffer.resize(curr_cr_buffer_len+nread);
        // todo: check the buffer size and fail if exceeds threshold
        memcpy(&(request->crbuffer[0])+curr_cr_buffer_len, buf->base, nread);
        free(buf->base);

        // check for Host header or CONNECT request
        // connect to server and create a pipe between server and client
        if(preProcess(request, loop))
        {
            logmsg("client %s sent request for %s\n", getClientInfo(request).c_str(), 
                                                      getServerInfo(request).c_str());

            struct addrinfo hints;;
            hints.ai_family = PF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            hints.ai_flags = 0;

            uv_getaddrinfo_t_r *resolver = new uv_getaddrinfo_t_r();
            resolver->request = request;

            int result = uv_getaddrinfo(loop, (uv_getaddrinfo_t*)resolver, on_resolved, 
                                   request->serverName.c_str(), request->serverPort.c_str(), &hints);

            if (result)
            {
                delete resolver;
                deleteRequest(request);
            }
        }
        else
        {
            uv_read_start((uv_stream_t*) client, alloc_buffer, on_client_init_read);
        }
    }
}

void on_new_connection(uv_stream_t *server, int status) 
{
    if (status < 0) 
    {
        logmsg("New connection error %s\n", uv_strerror(status));
        return;
    }

    Request *request = new Request();
    uv_tcp_t_r* client =  new uv_tcp_t_r();

    request->client = (uv_tcp_t*)client;
    client->request = request;

    uv_tcp_init(loop, (uv_tcp_t*)client);
    if (uv_accept(server, (uv_stream_t*) client) == 0)
    {
        fillClientDebugInfo(request);
        logmsg("new connection from : %s \n", getClientInfo(request).c_str());
        uv_read_start((uv_stream_t*) client, alloc_buffer, on_client_init_read);
    }
    else 
    {
        deleteRequest(request);
    }
}


int main() 
{
    uv_tcp_t server;
    struct sockaddr_in addr;

    loop = uv_default_loop();

    uv_tcp_init(loop, &server);

    logmsg("server listening on port %d\n", DEFAULT_PORT);
    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &addr);

    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
    int r = uv_listen((uv_stream_t*) &server, DEFAULT_BACKLOG, on_new_connection);
    if (r) 
    {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }

    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}