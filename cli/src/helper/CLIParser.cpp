#include "helper/CLIParser.h"
#include <iostream>


void CLIParser::print() {
    for (const auto& arg : args) {
        std::cout << arg << std::endl;
    }
}

void CLIParser::parse() {
    for (const auto& arg : args) {
        
    }
}

void CLIParser::help() {
    helpText += generate_flags_text();
    std::cout << helpText << std::endl;
}

std::string CLIParser::generate_flags_text() {
    std::string flagsText;
    for (const auto& tuple : flags) {
        flagsText.append("    -");
        flagsText += std::get<1>(tuple);
        flagsText.append(" --");
        flagsText.append(std::get<0>(tuple));
        flagsText.append("  ");
        flagsText.append(std::get<3>(tuple));
        flagsText.append("\n");
    }
    return flagsText;
}

void CLIParser::add_flag(const std::string& flagName, const AnyFunction& associatedFunction, const std::string& helpText) {
    std::unordered_set<char> takenChars;
    for (const auto& flag: flags) {
        takenChars.insert(std::get<1>(flag));
    }
    char flagChar = flagName.at(0);
    const int SIZE_OF_ALPHABET = 26;
    while (takenChars.find(flagChar) != takenChars.end()) {
        flagChar = static_cast<char>('a' + (flagChar - 'a' + 1) % SIZE_OF_ALPHABET);
    }
    flags.emplace_back(flagName, flagChar, associatedFunction, helpText);
}