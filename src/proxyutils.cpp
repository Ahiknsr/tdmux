#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

const std::string HOSTKEY = "host: ";
const std::string headerDelimiter = "\r\n";
const std::string COLON = ":";
const std::string DEFAULT_PORT = "80";

void parseHost(const std::vector<char>& buffer, std::string& host, std::string& port)
{
    port = DEFAULT_PORT;
    host.clear();
    if (buffer.size() <= HOSTKEY.size())
        return;
    
    std::string buffer_s(&buffer[0]);
    std::transform(buffer_s.begin(), buffer_s.end(), buffer_s.begin(), ::tolower);
    
    auto hostIndex = buffer_s.find(HOSTKEY);
    //std::cout<<buffer_s<<"\n";
    if (hostIndex == std::string::npos)
        return;

    auto hostIndexEnd = buffer_s.find(headerDelimiter, hostIndex + HOSTKEY.size());
    if (hostIndexEnd == std::string::npos)
        return;

    host = buffer_s.substr(hostIndex+HOSTKEY.size(), 
                           hostIndexEnd-hostIndex-HOSTKEY.size());
    //std::cout<<host<<"\n";
    auto colonIndex = host.find(COLON);
    if (colonIndex == std::string::npos)
        return;
    port = host.substr(colonIndex+1, host.size()-colonIndex-1);
    host.resize(colonIndex);
}

void logmsg(const char* format, ...)
{
    time_t now_tm;
    char *now;

    now_tm = time(NULL);
    now = ctime(&now_tm);

    fprintf(stdout, "[%d] [%.22s] ", getpid(), now);
    va_list ap;
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
    fflush(stdout);
}