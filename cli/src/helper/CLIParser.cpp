#include "helper/CLIParser.h"
#include <iostream>


void CLIParser::print() {
    for (const auto& arg : args) {
        std::cout << arg << std::endl;
    }
}

void CLIParser::parse() {
    std::vector<bool> setPositions;
    for (int i = 0; i < args.size(); ++i) {
        if (args[i].at(0) == '-') {
            if (args[i].length() > 2 && args[i].at(1) == '-') {
                std::string charFlags = args[i].substr(2, std::string::npos);
                for (char charFlag : charFlags) {

                }
            } else {

            }
        }
    }
}

int CLIParser::findCharFlag(char charFlag) {
    for (const auto& flag : allFlags) {
        if (flag.flagChar == charFlag) {

        }
    }
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

void CLIParser::add_flag(const std::string& flagName, const AnyFunction& associatedFunction, const std::string& helpText) {
    std::unordered_set<char> takenChars;
    for (const auto& flag: allFlags) {
        takenChars.insert(flag.flagChar);
    }
    char flagChar = flagName.at(0);
    const int SIZE_OF_ALPHABET = 26;
    while (takenChars.find(flagChar) != takenChars.end()) {
        flagChar = static_cast<char>('a' + (flagChar - 'a' + 1) % SIZE_OF_ALPHABET);
    }
    allFlags.emplace_back(Flag {flagName, flagChar, associatedFunction, helpText});
}