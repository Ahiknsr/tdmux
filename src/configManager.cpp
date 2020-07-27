#include <configManager.h>

ConfigManager::ConfigManager(std::string configFilePath)
{
    FILE* configFile = fopen(configFilePath.c_str(), "r");
    char config[100];
    char *nl;
    while (fgets(config, 100, configFile) != nullptr)
    {
        if ((nl=strchr(config, '\n')) != NULL)
            *nl = '\0';
        puts(config);
    }
}

int ConfigManager::isEnabled(std::string configFile)
{
    UNUSEDPARAM(configFile);
    return {};
}

std::string ConfigManager::getValue(std::string configFile)
{
    UNUSEDPARAM(configFile);
    return {};
}