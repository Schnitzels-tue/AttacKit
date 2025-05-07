#include "helper/helper.h"
#include "helper/CLIParser.h"

#include <core.h>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {

    // Parse command line arguments
    std::vector<std::string> args(argv + 1, argv + argc);
    CLIParser parser(args);
    parser.add_flag("help", [&parser](const std::vector<std::string>&) { parser.help(); }, "Opens this help menu");
    // parser.add_flag("arp", []() {ARP::poisonArp();}, "env    Performs an ARP poisoning attack on the device with name 'env'");
    // parser.add_flag("dns", []() { DNS::spoofDns(); }, "dummy    Lorem Ipsum");
    // parser.add_flag("ssl", []() {SSL::stripSSL();}, "dummy    Lorem Ipsum");

    parser.help();

    ARP::useHelper();
    helper();

    ARP::poisonArp();
    return 0;
}
