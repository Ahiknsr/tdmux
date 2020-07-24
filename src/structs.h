#include <uv.h>

#define UNUSEDPARAM(x) (void)(x)

struct Request
{
    uv_tcp_t *client;
    uv_tcp_t *server;
    std::string clientIp;
    std::string clientPort;
    std::string serverName;
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
        serverName = "";
    }
    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;
    virtual ~Request(){};
};

struct uv_tcp_t_r
{
    uv_tcp_t client;
    Request *request;
};

struct uv_getaddrinfo_t_r
{
    uv_getaddrinfo_t resolver;
    Request *request;
};

struct uv_connect_t_r
{
    uv_connect_t connect;
    Request *request;
};

struct write_req_t
{
    uv_write_t req;
    uv_buf_t buf;
};