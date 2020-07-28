#include <algorithm>

#include <configManager.h>

ConfigManager::ConfigManager(std::string configFilePath)
{
    std::string line;
    std::ifstream configFile(configFilePath);
    if (configFile) 
    {
        while (std::getline(configFile, line)) 
        {
            auto sepIndex = line.find(DELIMITER);
            if (sepIndex == std::string::npos)
                continue;

            auto key = line.substr(0, sepIndex);
            auto value = line.substr(sepIndex+1, line.size()-sepIndex);
            std::transform(value.begin(), value.end(), value.begin(), ::toupper);

            if(value == ENABLED || value == DISABLED)
            {
                enabledMap[key] = (value == ENABLED) ? 1 : 0;
            }
            else
            {
                valuesMap[key] = line.substr(sepIndex+1, line.size()-sepIndex);
            }            
        }
        configFile.close();
    }
    else
    {
        logmsg("error opening configFile\n");
    }
}

int ConfigManager::isEnabled(std::string key)
{
    return enabledMap[key];
}

std::string ConfigManager::getValue(std::string key)
{
    return valuesMap[key];
}