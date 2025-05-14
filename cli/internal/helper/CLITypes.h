#pragma once
#include <functional>
#include <string>
#include <vector>

using AnyFunction = std::function<void(const std::vector<std::string>&)>;

struct InvokeableFunction {
    std::string flagName;
    AnyFunction function;
    std::vector<std::string> arguments;
};