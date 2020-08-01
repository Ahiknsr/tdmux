#pragma once

#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <uv.h>

#define UNUSEDPARAM(x) (void)(x)

enum Protocol
{
    UNKNOWN,
    HTTP,
    HTTPS,
    SSH,
    TLS,
};

struct Request
{
    uv_tcp_t *client;
    uv_tcp_t *server;
    FILE *logfile;
    SSL *clientssl;
    BIO *crbio; /* SSL reads from, we write to. */
    BIO *cwbio; /* SSL writes to, we read from. */
    std::string clientIp;
    std::string clientPort;
    std::string serverName;
    std::string serverIp;
    std::string serverPort;
    Protocol protocol;
    std::vector<char> crbuffer;
    std::vector<char> cwbuffer;
    std::vector<char> srbuffer;
    std::vector<char> swbuffer;

    Request()
    {
        client = nullptr;
        server = nullptr;
        logfile = nullptr;
        clientssl = nullptr;
        crbio = nullptr;
        cwbio = nullptr;
        serverIp = "";
        serverPort = "80";
        serverName = "";
        protocol = Protocol::UNKNOWN;
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