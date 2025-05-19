#include "helper/CLIExecutor.h"
#include "arp_poisoning/public.h"
#include "helper/CLIParser.h"
#include "helper/CLITypes.h"
#include "log.h"

#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

// Helper functions used inside executors
namespace {
inline std::string boolToString(bool value) { return value ? "true" : "false"; }

inline bool stringToBool(std::string &value) { return value == "true"; }

auto toOptional(const std::string &arg) -> std::optional<std::string> {
    return arg.empty() ? std::nullopt : std::optional<std::string>{arg};
}

template <typename Out>
void split(const std::string &str, char delim, Out result) {
    std::istringstream iss(str);
    std::string item;
    while (std::getline(iss, item, delim)) {
        *result++ = item;
    }
}

std::vector<std::string> split(const std::string &str, char delim) {
    std::vector<std::string> elems;
    split(str, delim, std::back_inserter(elems));
    return elems;
}
}; // namespace

void CLIExecutor::setHelp(bool value) { this->help = value; }

void CLIExecutor::setQuiet(bool value) { this->quiet = value; }

void CLIExecutor::doMeaningfulThing(std::vector<std::string> args) {
    const bool quiet = stringToBool(args[2]);
    if (quiet) {
        std::cout << args[0] << '\n';
    } else {
        std::cout << args[1] << '\n';
    }
}

void CLIExecutor::invokeArpPoison(std::vector<std::string> args) {
    const int ALL_OUT_NUM_ARGS = 3;
    const int SILENT_NUM_ARGS = 5;
    if ((!stringToBool(args[0]) && args.size() != ALL_OUT_NUM_ARGS) ||
        (stringToBool(args[0]) && args.size() != SILENT_NUM_ARGS)) {
        LOG_ERROR(
            "Found wrong number of arguments for executing poisoning attack");
    }
    if (!stringToBool(args[0])) { // all out
        ATK::ARP::allOutPoison(
            {.ifaceIpOrName = args[1], .attackerMac = toOptional(args[2])});
    } else { // silent
        std::vector<std::string> victimIps = split(args[3], ',');
        std::vector<std::string> ipsToSpoof = split(args[4], ',');
        std::unordered_set<std::string> victimIpsSet(victimIps.begin(),
                                                     victimIps.end());
        std::unordered_set<std::string> ipsToSpoofSet(ipsToSpoof.begin(),
                                                      ipsToSpoof.end());
        ATK::ARP::silentPoison(
            ATK::ARP::SilentPoisoningOptions{.ifaceIpOrName = args[1],
                                             .attackerMac = toOptional(args[2]),
                                             .victimIp = victimIpsSet,
                                             .ipsToSpoof = ipsToSpoofSet});
    }
}

void CLIExecutor::execute(CLIParser &parser) const {
    // First parse the commands and check if parsing went right
    auto parsedCli = parser.parse();
    if (!parsedCli) {
        LOG_ERROR("Error while parsing command");
        return;
    }

    // We first process the functions that are associated with a priority flag
    for (const auto &parsedFunction : *parsedCli) {
        if (parsedFunction.options.priorityFlag) {
            invokeFunction(parsedFunction);
        }
    }

    // If the help flag is set, we ignore everything else and immediately print
    // the help menu
    if (this->help) {
        parser.printHelp();
        return;
    }

    // For all remaining functions that weren't priority, execute them while
    // paying attention to their FlagOptions
    for (const auto &parsedFunction : *parsedCli) {
        if (parsedFunction.options.priorityFlag) {
            continue;
        }

        auto parsedArguments = parsedFunction.arguments;
        if (parsedFunction.options.sensitiveToQuiet) {
            parsedArguments.insert(parsedArguments.begin(),
                                   boolToString(this->quiet));
        }

        parsedFunction.function(parsedArguments);
    }
}

void CLIExecutor::invokeFunction(const InvocableFunction &invocableFunction) {
    invocableFunction.function(invocableFunction.arguments);
}
