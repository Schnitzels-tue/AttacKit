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

        parser.add_flag(
            UnparsedFlag{"help",
                         [&executor](const std::vector<std::string> &) {
                             executor.setHelp(true);
                         },
                         "Show this help menu",
                         {0},
                         priorityFlagOpts});

        parser.add_flag(
            UnparsedFlag{"quiet",
                         [&executor](const std::vector<std::string> &) {
                             executor.setQuiet(true);
                         },
                         "Silent mode; targets specific IPs/domains; "
                         "incompatible with --all-out",
                         {0},
                         priorityFlagOpts});

        parser.add_flag(UnparsedFlag{
            "all-out",
            [&executor](const std::vector<std::string> &) {
                executor.setQuiet(false);
            },
            "Aggressive mode; targets all; incompatible with --quiet",
            {0},
            priorityFlagOpts});

        parser.add_flag(UnparsedFlag{
            "arp",
            CLIExecutor::invokeArpPoison,
            "ARP spoofing; attackerMac optional; victimIp/ipToSpoof required "
            "in quiet mode; supports comma-separated lists",
            {2, 4},
            sensitiveOpts});

        parser.add_flag(
            UnparsedFlag{"dns",
                         CLIExecutor::invokeDnsSpoofing,
                         "DNS spoofing; victimIps/domainsToSpoof required in "
                         "quiet mode; all queries targeted in all-out mode",
                         {2, 4},
                         sensitiveOpts});

        parser.add_flag(
            UnparsedFlag{"ssldns",
                         CLIExecutor::invokeSslStrippingDns,
                         "DNS-based SSL stripping; victimIps/domainsToStrip "
                         "required in quiet mode",
                         {2, 4},
                         sensitiveOpts});

        parser.add_flag(
            UnparsedFlag{"sslarp",
                         CLIExecutor::invokeSslStrippingArp,
                         "ARP-based SSL stripping; victimIps/domainsToStrip "
                         "required in quiet mode",
                         {1, 3},
                         sensitiveOpts});
        executor.execute(parser);
    } catch (const std::exception &e) {
        LOG_ERROR(std::string("Unhandled exception: ") + e.what());
        return 1;
    }
    return 0;
}
