#include "common/common.h"
#include "helper/CLIExecutor.h"
#include "helper/CLITypes.h"
#include "log.h"

#include <exception>
#include <helper/CLIParser.h>
#include <string>
#include <vector>

/**
 * Main function for the CLI. Everything called here will be executed when
 * AttacKit.exe is called in the command line.
 */
int main(int argc, char *argv[]) noexcept(false) {

    if (argc > 0) {
        // False-positive warning
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ATK::Common::setProcessName(std::string(argv[0]));
    }
    try {

        // Parse command line arguments
        const std::vector<std::string> args(argv + 1, argv + argc);
        CLIParser parser(args);
        CLIExecutor executor;

        FlagOptions priorityFlagOpts;
        priorityFlagOpts.priorityFlag = true;

        FlagOptions sensitiveOpts;
        sensitiveOpts.sensitiveToQuiet = true;

        // Add each individual flag to the parser before parsing the arguments
        parser.add_flag(
            UnparsedFlag{"help",
                         [&executor](const std::vector<std::string> &) {
                             executor.setHelp(true);
                         },
                         "Opens this help menu",
                         {0},
                         priorityFlagOpts});
        parser.add_flag(UnparsedFlag{
            "quiet",
            [&executor](const std::vector<std::string> &) {
                executor.setQuiet(true);
            },
            "Sets quiet to true. Has an effect on some functions. Calling this "
            "together with the all out flag causes undefined behaviour",
            {0},
            priorityFlagOpts});
        parser.add_flag(UnparsedFlag{
            "all-out",
            [&executor](const std::vector<std::string> &) {
                executor.setQuiet(false);
            },
            "Sets quiet to false. Has an effect on some functions. Calling "
            "this "
            "together with the quiet flag causes undefined behaviour",
            {0},
            priorityFlagOpts});
        parser.add_flag(UnparsedFlag{
            "arp",
            CLIExecutor::invokeArpPoison,
            "ifaceIpOrName  [attackerMac]  [victimIp]  [ipToSpoof]    Performs "
            "an ARP spoofing attack with the given arguments. Although "
            "attackerMac is always optional, victimIp and ipToSpoof are "
            "required when the quiet flag is passed. To pass multiple victim "
            "IPs and/or IPs to spoof, separate the IPs with commas, e.g. "
            "192.0.0.1,127.0.0.1. By default runs in all-out mode.",
            {2, 4},
            sensitiveOpts});
        parser.add_flag(UnparsedFlag{"dns",
                                     CLIExecutor::invokeDnsSpoofing,
                                     "blah blah blah",
                                     {4},
                                     sensitiveOpts});
        parser.add_flag(UnparsedFlag{"sslarp",
                                     CLIExecutor::invokeSslStrippingArp,
                                     "ifaceIpOrName  victimIps  domainsToStrip",
                                     {3},
                                     sensitiveOpts});
        parser.add_flag(UnparsedFlag{"ssldns",
                                     CLIExecutor::invokeSslStrippingDns,
                                     "ifaceIpOrName  victimIps  domainsToStrip",
                                     {3},
                                     sensitiveOpts});
        executor.execute(parser);
    } catch (const std::exception &e) {
        LOG_ERROR(std::string("Unhandled exception: ") + e.what());
        return 1;
    }
    return 0;
}
