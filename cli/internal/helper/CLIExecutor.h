#pragma once

#include "helper/CLIParser.h"
#include <string>
#include <vector>

class CLIExecutor {
    bool help = false;
    bool quiet = false;

  public:
    static void invokeArpPoison(std::vector<std::string> args);
    static void doMeaningfulThing(std::vector<std::string> args);
    /**
     * Will simply call the passed function with the given arguments.
     */
    static void invokeFunction(const AnyFunction &,
                               const std::vector<std::string> &);
    void setHelp(bool);
    void setQuiet(bool);
    void execute(CLIParser &) const;
};