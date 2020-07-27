#include <stdio.h>
#include <string.h>

#include <map>
#include <string>

#include <structs.h>


class ConfigManager
{
    public:
        ConfigManager(std::string configFile);
        int isEnabled(std::string key);
        std::string getValue(std::string key);

    private:
        std::string HTTPLOGGING = "HTTPLOGGING";
        std::map<std::string, int> defaultBools{{HTTPLOGGING, 1}};
};