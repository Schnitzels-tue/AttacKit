#include "helper/CLIParser.h"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {

    // Parse command line arguments
    std::vector<std::string> args(argv + 1, argv + argc);
    CLIParser parser(args);
    parser.add_flag("help", [&parser](const std::vector<std::string>&) { parser.help(); }, "Opens this help menu", 0);
    // parser.add_flag("arp", []() {ARP::poisonArp();}, "env    Performs an ARP poisoning attack on the device with name 'env'");
    // parser.add_flag("dns", []() { DNS::spoofDns(); }, "dummy    Lorem Ipsum");
    // parser.add_flag("ssl", []() {SSL::stripSSL();}, "dummy    Lorem Ipsum");

    std::optional<std::vector<CLIParser::InvokeableFunction>> parsedFunctions = parser.parse();
    if (parsedFunctions) {
        for (const auto& parsedFunction : *parsedFunctions) {
            CLIParser::invokeFunction(parsedFunction.function, parsedFunction.arguments);
        }
    }
    return 0;
}
