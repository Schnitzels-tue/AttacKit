#include "arp_poisoning/public.h"
#include "helper/CLIExecutor.h"
#include <helper/CLIParser.h>
#include <vector>


int main(int argc, char *argv[]) {
    //ATK::ARP::AllOutPoisonOptions options{.ifaceIpOrName = "en0"};

    //ATK::ARP::allOutPoison(options);

    // Parse command line arguments
    std::vector<std::string> args(argv + 1, argv + argc);
    CLIParser parser(args);
    CLIExecutor executor;

    parser.add_flag("help", [&executor](const std::vector<std::string>&) { executor.setHelp(true); }, "Opens this help menu", {0}, FlagOptions {.priorityFlag=true});
    executor.execute(parser);
}
