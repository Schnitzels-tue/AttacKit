#pragma once

#include "helper/CLIParser.h"
#include <string>
#include <vector>

class CLIExecutor {
    bool help = false;
    bool quiet = false;
    static void invokeArpPoison(std::vector<std::string> args);

public:
    void setHelp(bool);
    void setQuiet(bool);
    void execute(CLIParser&) const;
};