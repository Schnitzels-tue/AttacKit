#include "helper/CLIExecutor.h"
#include <helper/CLIParser.h>
#include <vector>

int main(int argc, char *argv[]) {

    // Parse command line arguments
    std::vector<std::string> args(argv + 1, argv + argc);
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
        "Sets quiet to false. Has an effect on some functions. Calling this "
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
}
