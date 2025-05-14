#pragma once

#include <functional>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "helper/CLITypes.h"

class CLIParser {


    std::string helpText;
    std::vector<std::string> args;

    std::vector<Flag> allFlags;

    std::optional<std::vector<InvokeableFunction>> flagsToFunctions(int&, std::vector<Flag>& setFlags);
    int findCharFlag(char);
    int findFlagName(const std::string&);

public:

    template <typename... Args>
    explicit CLIParser(Args... args) : args({ args... }), 
        helpText("This application is meant to provide the necessary functionality to perform ARP poisoning, "
        "DNS spoofing and SSL stripping.\n"
        "Usage: AttacKit [options] \n"
        "  options: \n") {}

    void printArguments();
    std::optional<std::vector<InvokeableFunction>> parse();
    static void invokeFunction(const AnyFunction&, const std::vector<std::string>&);
    
    void printHelp();

    std::string generate_flags_text();
    void add_flag(const std::string& flagName, 
        const AnyFunction& associatedFunction, 
        const std::string& helpText, 
        const std::set<int>& amountOfArguments,
        FlagOptions options = {});
};