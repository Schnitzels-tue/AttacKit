#include "helper/CLIParser.h"
#include "helper/CLITypes.h"
#include "log.h"

#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

void CLIParser::printArguments() {
    for (const auto &arg : args) {
        LOG_INFO(arg);
    }
}

std::optional<std::vector<InvocableFunction>>
CLIParser::flagsToFunctions(int &iteration, std::vector<Flag> &setFlags) {
    std::vector<InvocableFunction> parsedFunctions;

    for (const Flag &setFlag : setFlags) {
        if (setFlag.amountOfArguments.size() == 1 &&
            setFlag.amountOfArguments.find(0) !=
                setFlag.amountOfArguments.end()) {
            parsedFunctions.push_back(
                InvocableFunction{setFlag.flagFunction, {}, setFlag.options});
            continue;
        }
        std::vector<std::string> flagArgs;
        flagArgs.reserve(*setFlag.amountOfArguments.rbegin());
        const int beginIteration = iteration;
        for (int i = 0; i < *setFlag.amountOfArguments.rbegin(); ++i) {
            ++iteration;
            if (args.size() <= iteration &&
                setFlag.amountOfArguments.find(iteration - beginIteration -
                                               1) ==
                    setFlag.amountOfArguments.end()) {
                LOG_ERROR("Found an invalid amount of arguments for flag " +
                          setFlag.flagName);
                return std::nullopt;
            }
            if (args.size() <= iteration) {
                --iteration;
                break;
            }
            if (args[iteration].rfind('-', 0) == 0 &&
                setFlag.amountOfArguments.find(iteration - beginIteration -
                                               1) ==
                    setFlag.amountOfArguments.end()) {
                LOG_ERROR("Found an invalid amount of arguments for flag " +
                          setFlag.flagName);
                return std::nullopt;
            }
            if (args[iteration].rfind('-', 0) == 0) {
                --iteration;
                break;
            }

            flagArgs.push_back(args[iteration]);
        }

        parsedFunctions.push_back(
            InvocableFunction{setFlag.flagFunction, flagArgs, setFlag.options});
    }

    return parsedFunctions;
}

std::optional<std::vector<InvocableFunction>> CLIParser::parse() {
    std::vector<InvocableFunction> parsedFunctions;

    for (int i = 0; i < args.size(); ++i) {
        std::vector<Flag> setFlags;
        if (args[i].at(0) != '-') {
            LOG_ERROR("Found argument without corresponding flag: " + args[i]);
            return std::nullopt;
        }

        if (args[i].length() > 2 && args[i].at(1) == '-') {
            const std::string flagName = args[i].substr(2, std::string::npos);

            const int positionOfFlag = findFlagName(flagName);
            if (positionOfFlag == -1) {
                LOG_ERROR("Gave non-existent flag " + flagName);
                return std::nullopt;
            }

            setFlags.push_back(allFlags[positionOfFlag]);
        } else {
            const std::string charFlags = args[i].substr(1, std::string::npos);

            for (const char charFlag : charFlags) {
                const int positionOfFlag = findCharFlag(charFlag);
                if (positionOfFlag == -1) {
                    LOG_ERROR(std::string("Gave non-existent flag ")
                                  .append(1, charFlag));
                    return std::nullopt;
                }

                setFlags.push_back(allFlags[positionOfFlag]);
            }
        }

        if (setFlags.empty()) {
            LOG_ERROR("Something went wrong while processing the command");
            return std::nullopt;
        }

        auto optionalParsedFunctions = flagsToFunctions(i, setFlags);
        if (!optionalParsedFunctions) {
            return std::nullopt;
        }
        parsedFunctions.insert(parsedFunctions.end(),
                               (*optionalParsedFunctions).begin(),
                               (*optionalParsedFunctions).end());
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

void CLIParser::printHelp() {
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

void CLIParser::add_flag(const UnparsedFlag &unparsedFlag) {
    if (unparsedFlag.amountOfArguments.empty()) {
        LOG_ERROR("Amount of arguments was not specified correctly for flag " +
                  unparsedFlag.flagName);
        return;
    }
    if (helpText.empty()) {
        LOG_WARN("No help text was provided for flag " + unparsedFlag.flagName);
    }
    std::unordered_set<char> takenChars;
    std::unordered_set<std::string> takenNames;

    for (const auto &flag : allFlags) {
        takenChars.insert(flag.flagChar);
        takenNames.insert(flag.flagName);
    }

    if (takenNames.find(unparsedFlag.flagName) != takenNames.end()) {
        LOG_ERROR("Tried adding a flag with name " + unparsedFlag.flagName +
                  " but it already exists");
    }

    char flagChar = unparsedFlag.flagName.at(0);
    const int SIZE_OF_ALPHABET = 26;
    while (takenChars.find(flagChar) != takenChars.end()) {
        flagChar =
            static_cast<char>('a' + ((flagChar - 'a' + 1) % SIZE_OF_ALPHABET));
    }

    allFlags.emplace_back(
        Flag{unparsedFlag.flagName, flagChar, unparsedFlag.flagFunction,
             helpText, unparsedFlag.amountOfArguments, unparsedFlag.options});
}
