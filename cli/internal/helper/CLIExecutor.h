#pragma once

#include "helper/CLIParser.h"
#include "helper/CLITypes.h"
#include <string>
#include <vector>

/**
 * Meant to execute the functions returned by CLIParser. Functions added to
 * flags are meant to be defined here for proper operational logic.
 */
class CLIExecutor {
    // Whether to show the help menu (when set to true, will ignore all other
    // instructions and simply show the help menu)
    bool help = false;

    bool quiet = false;

  public:
    /**
     * Function to invoke an ARP poisoning attack with the right parameters
     */
    static void invokeArpPoison(std::vector<std::string> args);

    static void doMeaningfulThing(std::vector<std::string> args);
    /**
     * Will simply call the passed function with the given arguments.
     */
    static void invokeFunction(const InvocableFunction &);

    /**
     * Sets the help field boolean to the specified value.
     */
    void setHelp(bool);

    /**
     * Sets the quiet field boolean to the specified value.
     */
    void setQuiet(bool);

    /**
     * Handles the entire execution of the flags passed to the cli by using the
     * passed parser.
     *
     * Will respect the order that flags are passed in, and respects the
     * FlagOptions passed to each flag too.
     */
    void execute(CLIParser &) const;
};