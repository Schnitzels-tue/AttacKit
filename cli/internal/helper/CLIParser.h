#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

class CLIParser {
    using AnyFunction = std::function<void(const std::vector<std::string> &)>;

    struct Flag {
        std::string flagName;
        char flagChar;
        AnyFunction flagFunction;
        std::string flagHelpText;
        int amountOfArguments;
    };

    std::string helpText;
    std::vector<std::string> args;

    std::vector<Flag> allFlags;
    std::vector<Flag> setFlags;

  public:
    struct InvokeableFunction {
        AnyFunction function;
        std::vector<std::string> arguments;
    };

    template <typename... Args>
    explicit CLIParser(Args... args)
        : args({args...}),
          helpText("This application is meant to provide the necessary "
                   "functionality to perform ARP poisoning, "
                   "DNS spoofing and SSL stripping.\n"
                   "Usage: AttacKit [options] \n"
                   "  options: \n") {}

    void print();
    std::optional<std::vector<InvokeableFunction>> flagsToFunctions(int &);
    std::optional<std::vector<InvokeableFunction>> parse();
    static void invokeFunction(const AnyFunction &,
                               const std::vector<std::string> &);

    int findCharFlag(char);
    int findFlagName(const std::string &);

    void help();

    std::string generate_flags_text();
    void add_flag(const std::string &flagName,
                  const AnyFunction &associatedFunction,
                  const std::string &helpText, int amountOfArguments);
};
