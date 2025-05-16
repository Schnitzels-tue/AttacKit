#pragma once
#include <functional>
#include <set>
#include <string>
#include <vector>

using AnyFunction = std::function<void(const std::vector<std::string> &)>;

struct FlagOptions {
    bool sensitiveToQuiet = false;
    bool priorityFlag =
        false; // when a flag sets a boolean, they should be parsed first
    // can be extended
};

struct Flag {
    std::string flagName;
    char flagChar;
    AnyFunction flagFunction;
    std::string flagHelpText;
    std::set<int> amountOfArguments;
    FlagOptions options;
};

struct UnparsedFlag {
    std::string flagName;
    AnyFunction flagFunction;
    std::string flagHelpText;
    std::set<int> amountOfArguments;
    FlagOptions options = {};
};

struct InvocableFunction {
    AnyFunction function;
    std::vector<std::string> arguments;
    FlagOptions options;
};
