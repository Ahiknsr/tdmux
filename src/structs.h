#pragma once

#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <uv.h>

#define UNUSEDPARAM(x) (void)(x)

enum class Protocol
{
    UNKNOWN,
    HTTP,
    HTTPS,
    SSH,
    SSL,
};

enum SSL_STATUS 
{
    SSLSTATUS_OK,
    SSLSTATUS_WANT_IO,
    SSLSTATUS_CLOSED,
    SSLSTATUS_FAIL
};

/*
linchpin
*/
struct Request
{
    uv_tcp_t *client;
    uv_tcp_t *server;
    FILE *logfile;
    /* 
    used to decrypt data in crbuffer and 
    encrypt data in cwbuffer.
    */
    SSL *clientssl;
    BIO *crbio; /* SSL reads from, we write to. */
    BIO *cwbio; /* SSL writes to, we read from. */
    /*
    used to decrypt data in srbuffer and
    encrypt data in swbuffer.
    */
    SSL *serverssl;
    BIO *srbio; /* SSL reads from, we write to. */
    BIO *swbio; /* SSL writes to, we read from. */
    std::string clientIp;
    std::string clientPort;
    std::string serverName;
    std::string serverIp;
    std::string serverPort;
    Protocol protocol;
    std::vector<char> crbuffer; /* stores data read from client */
    std::vector<char> cwbuffer; /* stores data which needs to sent to client */
    std::vector<char> srbuffer; /* stores data read from server */
    std::vector<char> swbuffer; /* stores data whoch needs to sent to server */

    Request()
    {
        client = nullptr;
        server = nullptr;
        logfile = nullptr;
        clientssl = nullptr;
        crbio = nullptr;
        cwbio = nullptr;
        serverssl = nullptr;
        srbio = nullptr;
        swbio = nullptr;
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