#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include <cassert>
#include <cstring>
#include <string>
#include <vector> 

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

void parseHost(const std::vector<char>& buffer, std::string& host, std::string& port);

uv_loop_t *loop;
struct sockaddr_in addr;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    uv_connect_t con;
    uv_buf_t buf;
    uv_stream_t client;
} tcp_connect_buf;

typedef struct {
    uv_tcp_t client;
    std::vector<char> cdata; 
} uv_buffered_client;

typedef struct {
    uv_getaddrinfo_t resolver;
    uv_buffered_client* buffered_client;
} uv_buffered_getaddrinfo;

struct Request
{
    uv_tcp_t* client;
    uv_tcp_t* server;
    std::string serverIp;
    std::string serverPort;
    std::vector<char> crbuffer;
    std::vector<char> cwbuffer;
    std::vector<char> srbuffer;
    std::vector<char> swbuffer;
    Request()
    {
        client = nullptr;
        server = nullptr;
        serverIp = "";
        serverPort = "80";
    }
    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;
    virtual ~Request(){};
};

struct uv_tcp_t_r
{
    uv_tcp_t client;
    Request* request;
};

struct uv_getaddrinfo_t_r
{
    uv_getaddrinfo_t resolver;
    Request* request;
};

struct uv_connect_t_r
{
    uv_connect_t connect;
    Request* request;
};

void free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void free_handle(uv_handle_t* handle)
{
    uv_tcp_t_r* handle_r = (uv_tcp_t_r*)handle;
    delete handle;
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) 
{
    buf->base = (char*) malloc(suggested_size);
    buf->len = suggested_size;
}

void echo_write(uv_write_t *req, int status) 
{
    if (status) 
    {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free_write_req(req);
}

void on_write_end(uv_write_t *req, int status) 
{
  if (status == -1) 
  {
    fprintf(stderr, "error on_write_end");
    // free stuff
    return;
  }
  free_write_req(req);
}

void on_server_connect(uv_connect_t *req, int status) 
{
    uv_connect_t_r* req_r = (uv_connect_t_r*)req;
    Request* request = req_r->request;
    uv_tcp_t_r* server = (uv_tcp_t_r*)request->server;
    delete req_r;
    if (status < 0) 
    {
        fprintf(stderr, "error on_server_connect\n");
        uv_close((uv_handle_t*)(request->client), free_handle);
        delete server;
        return;
    }
    assert(status == 0);
    
  write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
  auto client_r_buffer_len = request->crbuffer.size();
  write_req->buf = uv_buf_init((char*) malloc(client_r_buffer_len), client_r_buffer_len);
  memcpy(write_req->buf.base, &request->crbuffer[0], client_r_buffer_len);

  uv_write((uv_write_t*)write_req, (uv_stream_t*)request->server, &write_req->buf, 1 /*nbufs*/, on_write_end);
}


void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) 
{
    uv_getaddrinfo_t_r *resolver_r = (uv_getaddrinfo_t_r*)resolver;
    Request *request = resolver_r->request;
    if (status < 0) 
    {
        fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
        uv_close((uv_handle_t*)(request->client), free_handle);
        delete request;
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

        uv_tcp_connect((uv_connect_t*)connect_req, (uv_tcp_t*)server, (const struct sockaddr*) res->ai_addr, on_server_connect);   
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
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        // don't have a server connection yet, just free the client handle
        uv_close((uv_handle_t*) client, free_handle);
        delete request;
        return;
    }
    else
    {
        auto curr_cr_buffer_len = request->crbuffer.size();
        request->crbuffer.resize(curr_cr_buffer_len+nread);
        // todo: check the buffer size and fail if exceeds threshold
        memcpy(&(request->crbuffer[0])+curr_cr_buffer_len, buf->base, nread);
        // printf("%s", &(buffered_client->cdata[0]));
        // can obtain the server connection
        parseHost(request->crbuffer, request->serverIp, request->serverPort);
        // connect to server and create a pipe between server and client
        if(request->serverIp.size()>0)
        {
            fprintf(stderr, "host %s port %s\n", request->serverIp.c_str(), request->serverPort.c_str());

            struct addrinfo hints;;
            hints.ai_family = PF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            hints.ai_flags = 0;

            uv_getaddrinfo_t_r *resolver = new uv_getaddrinfo_t_r();
            resolver->request = request;

            int result = uv_getaddrinfo(loop, (uv_getaddrinfo_t*)resolver,
                                   on_resolved, request->serverIp.c_str(), request->serverPort.c_str(), &hints);

            if (result)
            {
                delete resolver;
                delete request;
                uv_close((uv_handle_t*) client_r, free_handle);
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
        uv_close((uv_handle_t*) client, free_handle);
    }
}

int main() 
{
    loop = uv_default_loop();

    uv_tcp_t server;
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