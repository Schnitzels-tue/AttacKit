#include <functional>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>


void helper();

class CLIParser {

    std::string helpText =
        "This application is meant to provide the necessary functionality to perform ARP poisoning, "
        "DNS spoofing and SSL stripping.\n"
        "Usage: AttacKit [options] \n"
         "  options: \n";
    
    
    std::vector<std::string> args;
    std::unordered_map<std::string, std::pair<void (CLIParser::*)(), std::string>> flags;


public:
    template <typename... Args>
    explicit CLIParser(Args... args) : args({ args... }) {
        flags["help"] = std::make_pair(&CLIParser::help, "Opens this help menu");
        flags["arp"] = std::make_pair(&CLIParser::arp_poisoning, "env    Performs an ARP poisoning attack on the device with name 'env'");
        flags["dns"] = std::make_pair(&CLIParser::dns_spoofing, "dummy    Lorem Ipsum");
        flags["ssl"] = std::make_pair(&CLIParser::ssl_stripping, "dummy    Lorem Ipsum");
    }

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
            flagsText += tuple.first.at(0);
            flagsText.append(" --");
            flagsText.append(tuple.first);
            flagsText.append("  ");
            flagsText.append(tuple.second.second);
            flagsText.append("\n");
        }
        return flagsText;
    }
};