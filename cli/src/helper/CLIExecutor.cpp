#include "helper/CLIExecutor.h"
#include "arp_poisoning/public.h"
#include "log.h"

inline std::string boolToString(bool value) {
    return value ? "true" : "false";
}

inline bool stringToBool(std::string& value) {
    return value == "true";
}

void CLIExecutor::setHelp(bool value) {
    this->help = value;
}

void CLIExecutor::setQuiet(bool value) {
    this->quiet = value;
}

void CLIExecutor::invokeArpPoison(std::vector<std::string> args) {
    if (args.size() != 3) {
        LOG_ERROR("Found wrong number of arguments for executing poisoning attack");
    }
    if (!stringToBool(args[2])) {
        ATK::ARP::allOutPoison({
            .ifaceIpOrName = args[0],
            .attackerMac = args[1]
        });
    } else {
        // TODO(QuinnCaris)
    }
    
}

void CLIExecutor::execute(CLIParser& parser) const {
    if (this->help) {
        parser.printHelp();
        return;
    }
    auto parsedCli = parser.parse();
    if (!parsedCli) {
        LOG_ERROR("Error while parsing command");
        return;
    }
    for (const auto& parsedFunction : *parsedCli) {
        if (parsedFunction.options.sensitiveToQuiet) {
            auto parsedArguments = parsedFunction.arguments;
            parsedArguments.push_back(boolToString(this->quiet));
            parsedFunction.function(parsedArguments);
        }
    }
}