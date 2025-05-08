#pragma once

#include <functional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>


class CLIParser {
    using AnyFunction = std::function<void(const std::vector<std::string>&)>;

    struct Flag {
        std::string flagName;
        char flagChar;
        AnyFunction flagFunction; 
        std::string flagHelpText;
    };

    std::string helpText;
    std::vector<std::string> args;

    // Keys: string of flag name
    // Values: a pair in the format of (flagChar, function_to_call, helpText)
    std::vector<Flag> allFlags;
    std::vector<Flag> setFlags;

public:
    template <typename... Args>
    explicit CLIParser(Args... args) : args({ args... }), 
        helpText("This application is meant to provide the necessary functionality to perform ARP poisoning, "
        "DNS spoofing and SSL stripping.\n"
        "Usage: AttacKit [options] \n"
        "  options: \n") {}

    void print();
    void parse();
    int findCharFlag(char);
    void help();

    std::string generate_flags_text();
    void add_flag(const std::string& flagName, const AnyFunction& associatedFunction, const std::string& helpText);
};