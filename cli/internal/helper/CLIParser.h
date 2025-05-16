#pragma once

#include <optional>
#include <string>
#include <vector>

#include "helper/CLITypes.h"

class CLIParser {

    std::string helpText;
    std::vector<std::string> args;

    std::vector<Flag> allFlags;

    std::optional<std::vector<InvocableFunction>>
    flagsToFunctions(int &, std::vector<Flag> &setFlags);
    int findCharFlag(char);
    int findFlagName(const std::string &);
    std::string generate_flags_text();

  public:
    /**
     * Can easily be initialized with a vector of strings. Will set the local
     * private field args and set the general help text. This constructor does
     * not start the parsing process yet!
     */
    template <typename... Args>
    explicit CLIParser(Args... args)
        : args({args...}),
          helpText("This application is meant to provide the necessary "
                   "functionality to perform ARP poisoning, "
                   "DNS spoofing and SSL stripping.\n"
                   "Usage: AttacKit [options] \n"
                   "  options: \n") {}

    /**
     * For debugging purposes, the arguments passed to the cli can be printed
     * with this function.
     */
    void printArguments();

    /**
     * Parses the arguments passed to the program.
     *
     * In case something goes wrong during this process, this function will
     * return std::nullopt.
     *
     * In case everything goes right, it will return a
     * vector of InvocableFunctions representing all flags and their arguments
     * passed in the cli.
     */
    std::optional<std::vector<InvocableFunction>> parse();

    /**
     * Will simply call the passed function with the given arguments.
     */
    static void invokeFunction(const AnyFunction &,
                               const std::vector<std::string> &);

    /**
     * Will print the full help menu. Needs an instance of CLIParser with all
     * needed flags.
     */
    void printHelp();

    /**
     * Adds a flag to parser instance. This does NOT mean this flag is used and
     * returned after parsing, but rather it's a notice that the flag exists.
     * The parser will check for flags added with this function when parsing the
     * cli arguments.
     */
    void add_flag(const UnparsedFlag &unparsedFlag);
};
