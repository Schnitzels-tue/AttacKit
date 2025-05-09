#include "helper/CLIParser.h"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {

    // Parse command line arguments
    std::vector<std::string> args(argv + 1, argv + argc);
    CLIParser parser(args);
    parser.add_flag("help", [&parser](const std::vector<std::string>&) { parser.help(); }, "Opens this help menu", 0);

    std::optional<std::vector<CLIParser::InvokeableFunction>> parsedFunctions = parser.parse();
    if (parsedFunctions) {
        for (const auto& parsedFunction : *parsedFunctions) {
            CLIParser::invokeFunction(parsedFunction.function, parsedFunction.arguments);
        }
    }
    return 0;
}
