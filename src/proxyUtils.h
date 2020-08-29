#include <structs.h>

void logmsg(const char* format, ...);
void deleteRequest(Request *request);
void free_write_req(uv_write_t *req);
void freeHandle(uv_handle_t *handle);
void on_write_end(uv_write_t *req, int status);
void fillClientDebugInfo(Request *request);
std::string getClientInfo(const Request *request);
std::string getServerInfo(const Request *request);
std::string getRequestInfo(const Request *request);
std::string getLogFileName(const Request *request);