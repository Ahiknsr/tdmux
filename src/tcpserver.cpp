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
#define UNUSEDPARAM(x) (void)(x)

void parseHost(const std::vector<char>& buffer, std::string& host, std::string& port);
void logmsg(const char* format, ...);

uv_loop_t *loop;

void free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void free_handle(uv_handle_t *handle)
{
    uv_tcp_t_r *handle_r = (uv_tcp_t_r*)handle;
    delete handle_r;
}

void destroyRequest(Request *request)
{
    if (request == nullptr)
        return;
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

void on_write_end(uv_write_t *req, int status) 
{
  if (status == -1) 
  {
    logmsg("error on_write_end");
    // free request?
  }
  free_write_req(req);
}

void on_client_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    uv_tcp_t_r* client_r = (uv_tcp_t_r*)client;
    Request* request = client_r->request;

    if(nread < 0)
    {
        if (nread != UV_EOF)
            logmsg("Read error %s\n", uv_err_name(nread));
        destroyRequest(request);
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
    logmsg("read from server\n");
    uv_tcp_t_r* server_r = (uv_tcp_t_r*)server;
    Request* request = server_r->request;

    if(nread < 0)
    {
        if (nread != UV_EOF)
            logmsg("Read error %s\n", uv_err_name(nread));
        destroyRequest(request);
        return;
    }
    else
    {
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
        destroyRequest(request);
        return;
    }
    assert(status == 0);
    
    write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
    auto client_r_buffer_len = request->crbuffer.size();
    write_req->buf = uv_buf_init((char*) malloc(client_r_buffer_len), client_r_buffer_len);
    memcpy(write_req->buf.base, &request->crbuffer[0], client_r_buffer_len);
    request->crbuffer.resize(0);

    logmsg("writing to server\n");
    uv_write((uv_write_t*)write_req, (uv_stream_t*)server, &write_req->buf, 1 /*nbufs*/, on_write_end);
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
        destroyRequest(request);
    }
    else
    {
        char addr[17] = {'\0'};
        uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
        fprintf(stderr, "ip addr is %s\n", addr);

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
        destroyRequest(request);
        return;
    }
    else
    {
        auto curr_cr_buffer_len = request->crbuffer.size();
        request->crbuffer.resize(curr_cr_buffer_len+nread);
        // todo: check the buffer size and fail if exceeds threshold
        memcpy(&(request->crbuffer[0])+curr_cr_buffer_len, buf->base, nread);
        free(buf->base);
        // printf("%s", &(buffered_client->cdata[0]));
        // can obtain the server connection
        parseHost(request->crbuffer, request->serverIp, request->serverPort);
        // connect to server and create a pipe between server and client
        if(request->serverIp.size()>0)
        {
            logmsg("host %s port %s\n", request->serverIp.c_str(), request->serverPort.c_str());

            struct addrinfo hints;;
            hints.ai_family = PF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            hints.ai_flags = 0;

            uv_getaddrinfo_t_r *resolver = new uv_getaddrinfo_t_r();
            resolver->request = request;

            int result = uv_getaddrinfo(loop, (uv_getaddrinfo_t*)resolver, on_resolved, 
                                   request->serverIp.c_str(), request->serverPort.c_str(), &hints);

            if (result)
            {
                delete resolver;
                destroyRequest(request);
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
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        // error!
        return;
    }

    Request *request = new Request();
    uv_tcp_t_r* client =  new uv_tcp_t_r();

    request->client = (uv_tcp_t*)client;
    client->request = request;

    uv_tcp_init(loop, (uv_tcp_t*)client);
    if (uv_accept(server, (uv_stream_t*) client) == 0)
    {
        uv_read_start((uv_stream_t*) client, alloc_buffer, on_client_init_read);
    }
    else 
    {
        destroyRequest(request);
    }
}

int main() 
{
    loop = uv_default_loop();

    uv_tcp_t server;
    struct sockaddr_in addr;
    uv_tcp_init(loop, &server);

    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &addr);

    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
    int r = uv_listen((uv_stream_t*) &server, DEFAULT_BACKLOG, on_new_connection);
    if (r) 
    {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    return uv_run(loop, UV_RUN_DEFAULT);
}