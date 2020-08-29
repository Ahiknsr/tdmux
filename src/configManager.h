#pragma once

#include <fstream>
#include <map>
#include <string>

#include <structs.h>
#include <proxyUtils.h>

class ConfigManager
{
    public:
        ConfigManager(std::string configFile = "config");
        int isEnabled(std::string key);
        std::string getValue(std::string key);

        // keys
        const std::string HTTPLOGGING = "HTTPLOGGING";
        const std::string MITMHTTPCONNECT = "MITMHTTPCONNECT";

    private:
        const std::string DELIMITER = "=";
        const std::string ENABLED = "TRUE";
        const std::string DISABLED = "FALSE";

        std::map<std::string, int> enabledMap{{HTTPLOGGING, 1}, {MITMHTTPCONNECT, 1}};
        std::map<std::string, std::string> valuesMap{};
};