#include "arp_poisoning/public.h"
#include "helper/CLIExecutor.h"
#include "helper/CLITypes.h"
#include "log.h"

#include <exception>
#include <helper/CLIParser.h>
#include <optional>
#include <string>
#include <vector>

int main(int argc, char *argv[]) noexcept(false) {
    try {
        const ATK::ARP::SilentPoisoningOptions options{
            .ifaceIpOrName = "en0",
            .attackerMac = std::nullopt,
            .victimIp = {"192.168.178.1"},
            .ipsToSpoof = {"192.172.199.1"}};

        ATK::ARP::silentPoison(options);

        // Parse command line arguments
        const std::vector<std::string> args(argv + 1, argv + argc);
        CLIParser parser(args);
        CLIExecutor executor;

        parser.add_flag(
            "help",
            [&executor](const std::vector<std::string> &) {
                executor.setHelp(true);
            },
            "Opens this help menu", {0}, FlagOptions{.priorityFlag = true});
        parser.add_flag(
            "quiet",
            [&executor](const std::vector<std::string> &) {
                executor.setQuiet(true);
            },
            "Sets quiet to true. Has an effect on some functions. Calling this "
            "together with the all out flag causes undefined behaviour",
            {0}, FlagOptions{.priorityFlag = true});
        parser.add_flag(
            "all-out",
            [&executor](const std::vector<std::string> &) {
                executor.setQuiet(false);
            },
            "Sets quiet to false. Has an effect on some functions. Calling "
            "this "
            "together with the quiet flag causes undefined behaviour",
            {0}, FlagOptions{.priorityFlag = true});
        parser.add_flag(
            "meaning",
            [](const std::vector<std::string> &args) {
                CLIExecutor::doMeaningfulThing(args);
            },
            "x  y    Does some kind of meaningful thing", {2},
            FlagOptions{.sensitiveToQuiet = true});

        executor.execute(parser);
    } catch (const std::exception &e) {
        LOG_ERROR(std::string("Unhandled exception: ") + e.what());
        return 1;
    }
    return 0;
}
