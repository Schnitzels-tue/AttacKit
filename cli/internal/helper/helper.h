#include <functional>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>


void helper();

class CLIParser {
    using AnyFunction = std::function<void(const std::vector<std::string>&)>;

    std::string helpText =
        "This application is meant to provide the necessary functionality to perform ARP poisoning, "
        "DNS spoofing and SSL stripping.\n"
        "Usage: AttacKit [options] \n"
         "  options: \n";
    
    
    std::vector<std::string> args;
    // Keys: string of flag name
    // Values: a pair in the format of (function_to_call, helpText)
    std::unordered_map<std::pair<char, std::string>, std::pair<AnyFunction, std::string>> flags;


public:
    template <typename... Args>
    explicit CLIParser(Args... args) : args({ args... }) {}

    void print() {
        for (const auto& arg : args) {
            std::cout << arg << std::endl;
        }
    }

    void parse() {
        for (const auto& arg : args) {
            
        }
    }

    void help() {
        helpText += generate_flags_text();
        std::cout << helpText << std::endl;
    }

    void arp_poisoning() {

    }

    void dns_spoofing() {

    }

    void ssl_stripping() {

    }

    std::string generate_flags_text() {
        std::string flagsText;
        for (const auto& tuple : flags) {
            flagsText.append("    -");
            flagsText += tuple.first.first;
            flagsText.append(" --");
            flagsText.append(tuple.first.second);
            flagsText.append("  ");
            flagsText.append(tuple.second.second);
            flagsText.append("\n");
        }
        return flagsText;
    }

    void add_flag(const std::string& flagName, const AnyFunction& associatedFunction, const std::string& helpText) {
        std::unordered_set<char> takenChars;
        for (const auto& flag: flags) {
            takenChars.insert(flag.first.first);
        }
        char flagChar = flagName.at(0);
        const int SIZE_OF_ALPHABET = 26;
        while (takenChars.find(flagChar) != takenChars.end()) {
            flagChar = static_cast<char>('a' + (flagChar - 'a' + 1) % SIZE_OF_ALPHABET);
        }
        flags[std::make_pair(flagChar, flagName)] = std::make_pair(associatedFunction, helpText);
    }
};