#include "helper/CLIParser.h"
#include <iostream>
#include <unordered_set>

void CLIParser::print() {
    for (const auto &arg : args) {
        std::cout << arg << '\n';
    }
}

std::optional<std::vector<CLIParser::InvokeableFunction>>
CLIParser::flagsToFunctions(int &iteration) {
    std::vector<InvokeableFunction> parsedFunctions;

    for (const Flag &setFlag : setFlags) {
        std::vector<std::string> flagArgs;
        flagArgs.reserve(setFlag.amountOfArguments);

        for (int j = 0; j < setFlag.amountOfArguments; ++j) {
            if (args.size() <= ++iteration) {
                std::cout << "Did not supply enough arguments for flag "
                          << setFlag.flagName << '\n';
                return std::nullopt;
            }
            flagArgs.push_back(args[iteration]);
        }

        parsedFunctions.push_back(
            InvokeableFunction{setFlag.flagFunction, flagArgs});
    }

    return parsedFunctions;
}

std::optional<std::vector<CLIParser::InvokeableFunction>> CLIParser::parse() {
    std::vector<InvokeableFunction> parsedFunctions;

    for (int i = 0; i < args.size(); ++i) {
        std::vector<Flag> setFlags;

        if (args[i].at(0) != '-') {
            std::cout << "Found argument without corresponding flag: "
                      << args[i] << '\n';
            return std::nullopt;
        }

        if (args[i].length() > 2 && args[i].at(1) == '-') {
            const std::string flagName = args[i].substr(2, std::string::npos);

            const int positionOfFlag = findFlagName(flagName);
            if (positionOfFlag == -1) {
                std::cout << "Gave non-existent flag " << flagName << '\n';
                return std::nullopt;
            }

            setFlags.push_back(allFlags[positionOfFlag]);
        } else {
            const std::string charFlags = args[i].substr(1, std::string::npos);

            for (const char charFlag : charFlags) {
                const int positionOfFlag = findCharFlag(charFlag);
                if (positionOfFlag == -1) {
                    std::cout << "Gave non-existent flag " << charFlag << '\n';
                    return std::nullopt;
                }

                setFlags.push_back(allFlags[positionOfFlag]);
            }
        }

        if (setFlags.empty()) {
            std::cerr << "Something went wrong while processing the command."
                      << '\n';
        }

        auto optionalParsedFunctions = flagsToFunctions(i);
        if (!optionalParsedFunctions) {
            return std::nullopt;
        }
        parsedFunctions = *optionalParsedFunctions;
    }
    return parsedFunctions;
}

void CLIParser::invokeFunction(const AnyFunction &flagFunction,
                               const std::vector<std::string> &arguments) {
    flagFunction(arguments);
}

int CLIParser::findCharFlag(char charFlag) {
    for (int i = 0; i < allFlags.size(); ++i) {
        if (allFlags[i].flagChar == charFlag) {
            return i;
        }
    }

    return -1;
}

int CLIParser::findFlagName(const std::string &flagName) {
    for (int i = 0; i < allFlags.size(); ++i) {
        if (allFlags[i].flagName == flagName) {
            return i;
        }
    }

    return -1;
}

void CLIParser::help() {
    helpText += generate_flags_text();
    std::cout << helpText << '\n';
}

std::string CLIParser::generate_flags_text() {
    std::string flagsText;

    for (const auto &flag : allFlags) {
        flagsText.append("    -");
        flagsText += flag.flagChar;
        flagsText.append(" --");
        flagsText.append(flag.flagName);
        flagsText.append("  ");
        flagsText.append(flag.flagHelpText);
        flagsText.append("\n");
    }

    return flagsText;
}

void CLIParser::add_flag(const std::string &flagName,
                         const AnyFunction &associatedFunction,
                         const std::string &helpText,
                         const int amountOfArguments) {
    std::unordered_set<char> takenChars;

    for (const auto &flag : allFlags) {
        takenChars.insert(flag.flagChar);
    }

    char flagChar = flagName.at(0);
    const int SIZE_OF_ALPHABET = 26;
    while (takenChars.find(flagChar) != takenChars.end()) {
        flagChar =
            static_cast<char>('a' + ((flagChar - 'a' + 1) % SIZE_OF_ALPHABET));
    }

    allFlags.emplace_back(Flag{flagName, flagChar, associatedFunction, helpText,
                               amountOfArguments});
}
