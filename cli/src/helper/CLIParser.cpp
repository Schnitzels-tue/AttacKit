#include "helper/CLIParser.h"
#include <iostream>


void CLIParser::print() {
    for (const auto& arg : args) {
        std::cout << arg << std::endl;
    }
}

std::optional<std::vector<CLIParser::InvokeableFunction>> CLIParser::parse() {
    std::vector<InvokeableFunction> parsedFunctions;
    for (int i = 0; i < args.size(); ++i) {
        std::vector<Flag> setFlags;
        if (args[i].at(0) != '-') {
            std::cout << "Found argument without corresponding flag: " << args[i] << std::endl;
            return std::nullopt;
        }
        if (args[i].length() > 2 && args[i].at(1) == '-') {
            std::string flagName = args[i].substr(2, std::string::npos);
            int positionOfFlag = findFlagName(flagName);
            if (positionOfFlag == -1) {
                std::cout << "Gave non-existent flag " << flagName << std::endl;
                return std::nullopt;
            }
            setFlags.push_back(allFlags[positionOfFlag]);
        } else {
            std::string charFlags = args[i].substr(1, std::string::npos);
            for (char charFlag : charFlags) {
                int positionOfFlag = findCharFlag(charFlag);
                if (positionOfFlag == -1) {
                    std::cout << "Gave non-existent flag " << charFlag << std::endl;
                    return std::nullopt;
                }
                setFlags.push_back(allFlags[positionOfFlag]);
            }
        }

        if (setFlags.empty()) {
            std::cerr << "Something went wrong while processing the command." << std::endl;
        }
        for (const Flag& setFlag : setFlags) {
            std::vector<std::string> flagArgs;
            flagArgs.reserve(setFlag.amountOfArguments);
            for (int j = 0; j < setFlag.amountOfArguments; ++j) {
                flagArgs.push_back(args[++i]);
            }
            parsedFunctions.push_back(InvokeableFunction {setFlag.flagFunction, flagArgs});
        }
    }
    return parsedFunctions;
}

void CLIParser::invokeFunction(const AnyFunction& flagFunction, const std::vector<std::string>& arguments) {
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

int CLIParser::findFlagName(const std::string& flagName) {
    for (int i = 0; i < allFlags.size(); ++i) {
        if (allFlags[i].flagName == flagName) {
            return i;
        }
    }
    return -1;
}

void CLIParser::help() {
    helpText += generate_flags_text();
    std::cout << helpText << std::endl;
}

std::string CLIParser::generate_flags_text() {
    std::string flagsText;
    for (const auto& flag : allFlags) {
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

void CLIParser::add_flag(const std::string& flagName, 
    const AnyFunction& associatedFunction, 
    const std::string& helpText,
    const int amountOfArguments) {
    std::unordered_set<char> takenChars;
    for (const auto& flag: allFlags) {
        takenChars.insert(flag.flagChar);
    }
    char flagChar = flagName.at(0);
    const int SIZE_OF_ALPHABET = 26;
    while (takenChars.find(flagChar) != takenChars.end()) {
        flagChar = static_cast<char>('a' + (flagChar - 'a' + 1) % SIZE_OF_ALPHABET);
    }
    allFlags.emplace_back(Flag {flagName, flagChar, associatedFunction, helpText, amountOfArguments});
}