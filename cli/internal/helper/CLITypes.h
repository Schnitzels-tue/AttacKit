#pragma once
#include <functional>
#include <string>
#include <vector>

using AnyFunction = std::function<void(const std::vector<std::string>&)>;

struct FlagOptions {
    bool sensitiveToQuiet = false;
    // can be extended
};

struct Flag {
    std::string flagName;
    char flagChar;
    AnyFunction flagFunction;
    std::string flagHelpText;
    int amountOfArguments;
    FlagOptions options;
};

struct InvokeableFunction {
    AnyFunction function;
    std::vector<std::string> arguments;
    FlagOptions options;
};
