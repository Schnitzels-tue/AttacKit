#pragma once

#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

class CLIParser {
    using AnyFunction = std::function<void(const std::vector<std::string>&)>;

    std::string helpText;
    std::vector<std::string> args;

    // Keys: string of flag name
    // Values: a pair in the format of (flagChar, function_to_call, helpText)
    std::unordered_map<std::string, std::tuple<char, AnyFunction, std::string>> flags;

public:
    template <typename... Args>
    explicit CLIParser(Args... args) : args({ args... }) {}

    void print();
    void parse();
    void help();

    std::string generate_flags_text();
    void add_flag(const std::string& flagName, const AnyFunction& associatedFunction, const std::string& helpText);
};