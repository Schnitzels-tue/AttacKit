#include "helper/CLIParser.h"

#include <iostream>
#include <string>
#include <vector>

void testFunction(int x, int y) {
    int z = x + y;
    std::cout << z << std::endl;
}

int main(int argc, char* argv[]) {

    // Parse command line arguments
    std::vector<std::string> args(argv + 1, argv + argc);
    CLIParser parser(args);
    parser.add_flag("help", [&parser](const std::vector<std::string>&) { parser.help(); }, "Opens this help menu", 0);
    parser.add_flag("testfunc", [](const std::vector<std::string>& funcArgs) {
        try {
            int x = std::stoi(funcArgs[0]);
            int y = std::stoi(funcArgs[1]);
            testFunction(x, y);
        } catch (const std::invalid_argument& e) {
            std::cout << "Invalid arguments, sum arguments are not numbers" << std::endl;
        }
    }, "x  y    Just a function to sum two numbers", 2);

    std::optional<std::vector<CLIParser::InvokeableFunction>> parsedFunctions = parser.parse();
    if (parsedFunctions) {
        for (const auto& parsedFunction : *parsedFunctions) {
            CLIParser::invokeFunction(parsedFunction.function, parsedFunction.arguments);
        }
    }


    return 0;
}
