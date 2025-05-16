#pragma once
#include <functional>
#include <set>
#include <string>
#include <utility>
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

struct InvokeableFunction {
  public:
    InvokeableFunction(AnyFunction function, std::vector<std::string> arguments,
                       FlagOptions options)
        : function(std::move(function)), arguments(std::move(arguments)),
          options(options) {}

    // constructor must exist for performant vector emplacing, fixed in c++20,
    // will also remove the linting issue
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes) constructor
    AnyFunction function;
    std::vector<std::string> arguments;
    FlagOptions options;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};
