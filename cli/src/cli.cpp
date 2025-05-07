#include "helper/helper.h"

#include <core.h>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {

    // Parse command line arguments
    std::vector<std::string> args(argv + 1, argv + argc);
    CLIParser parser(args);

    parser.help();

    ARP::useHelper();
    helper();

    ARP::poisonArp();
    return 0;
}
