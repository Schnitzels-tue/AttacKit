#pragma once
#include <functional>
#include <set>
#include <string>
#include <vector>

/**
 * Simple alias for a function that is meant to be passed to a flag.
 * Although it says "any" function, it only accepts functions that return void
 * and accept a pointer to a vector of strings as a parameter.
 */
using AnyFunction = std::function<void(const std::vector<std::string> &)>;

/**
 * Specific options set to a flag. Specifies a certain behaviour a flag should
 * meet, which will be taken into consideration when the flags are executed.
 */
struct FlagOptions {
    bool sensitiveToQuiet = false;
    bool priorityFlag =
        false; // when a flag sets a boolean, they should be parsed first
    // can be extended
};

/**
 * General Flag type. It stores everything associated with a certain specific
 * flag.
 */
struct Flag {
    std::string flagName;
    char flagChar;
    AnyFunction flagFunction;
    std::string flagHelpText;
    std::set<int> amountOfArguments;
    FlagOptions options;
};

/**
 * Similar to the Flag struct, but does not have flagChar since the parser has
 * to calculate this by itself.
 */
struct UnparsedFlag {
    std::string flagName;
    AnyFunction flagFunction;
    std::string flagHelpText;
    std::set<int> amountOfArguments;
    FlagOptions options = {};
};

/**
 * A function that can simply be called with its function and arguments.
 *
 * Example:
 * InvocableFunction test;
 * test.function(test.arguments)
 *
 * Be sure to keep track of the options since this might impact when or how the
 * function within has to behave.
 */
struct InvocableFunction {
    AnyFunction function;
    std::vector<std::string> arguments;
    FlagOptions options;
};
