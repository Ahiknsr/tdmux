#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#define log(x) printf("%s\n", x);

uv_loop_t *loop;

typedef struct 
{
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

void free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}


void free_handle(uv_handle_t* handle)
{
  free(handle);
}

void on_read(uv_stream_t *server, ssize_t nread, const uv_buf_t* buf) 
{
  if(nread < 0)
  {
        printf("connection closed\n");
        uv_close((uv_handle_t*) server, free_handle);
  }
  else
  {
      printf("%s", buf->base);
  }
  if(buf->base)
    free(buf->base);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) 
{
    buf->base = (char*) malloc(suggested_size);
    buf->len = suggested_size;
}

void on_write_end(uv_write_t *req, int status) 
{
  if (status == -1) 
  {
    fprintf(stderr, "error on_write_end");
    return;
  }
  free_write_req(req);
}

void on_connect(uv_connect_t *req, int status) 
{
  if (status < 0) 
  {
    fprintf(stderr, "error on_connect\n");
    return;
  }
  assert(status == 0);

  char *message = "GET / HTTP/1.1\r\nHost: localhost:8000\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0\r\n\r\n";
  int len = strlen(message);

  uv_stream_t* tcp = req->handle;

  write_req_t *write_req = (write_req_t*) malloc(sizeof(write_req_t));
  write_req->buf = uv_buf_init((char*) malloc(len), len);
  memcpy(write_req->buf.base, message, len);

  uv_write((uv_write_t*)write_req, tcp, &write_req->buf, 1 /*nbufs*/, on_write_end);
  uv_read_start(req->handle, alloc_buffer, on_read);
}

int main(void) {
    loop = uv_default_loop();

    uv_tcp_t* client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));

    uv_tcp_init(loop, client);

    struct sockaddr_in req_addr;
    uv_ip4_addr("127.0.0.1", 7000, &req_addr);
    //uv_ip4_addr("216.58.199.174", 80, &req_addr);

    uv_connect_t connect_req;

    uv_tcp_connect(&connect_req, client, (struct sockaddr*)&req_addr, on_connect);

    return uv_run(loop, UV_RUN_DEFAULT);
}