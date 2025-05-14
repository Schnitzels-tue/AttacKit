#pragma once

#include "helper/CLIParser.h"
#include <string>
#include <vector>

class CLIExecutor {
    bool help = false;
    bool quiet = false;
    void setHelp(bool);
    void setQuiet(bool);
    static void invokeArpPoison(std::vector<std::string> args);

public:
    void execute(CLIParser&) const;
};