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

void CLIExecutor::doMeaningfulThing(std::vector<std::string> args) {
    std::cout << "sus" << std::endl;
    bool quiet = stringToBool(args[2]);
    std::cout << "got here tho!" << std::endl;
    if (quiet) {
        std::cout << args[0] << std::endl;
    } else {
        std::cout << args[1] << std::endl;
    }
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
        LOG_INFO("Poisoning silently...");
        // TODO(QuinnCaris)
    }
    
}

void CLIExecutor::execute(CLIParser& parser) const {
    auto parsedCli = parser.parse();
    if (!parsedCli) {
        LOG_ERROR("Error while parsing command");
        return;
    }
    for (const auto& parsedFunction : *parsedCli) {
        if (parsedFunction.options.priorityFlag) {
            parsedFunction.function(parsedFunction.arguments);
        }
    }

    if (this->help) {
        parser.printHelp();
        return;
    }

    for (const auto& parsedFunction : *parsedCli) {
        if (parsedFunction.options.priorityFlag) {
            continue;
        }
        auto parsedArguments = parsedFunction.arguments;
        if (parsedFunction.options.sensitiveToQuiet) {
            parsedArguments.push_back(boolToString(this->quiet));
        }
        parsedFunction.function(parsedArguments);
    }
}