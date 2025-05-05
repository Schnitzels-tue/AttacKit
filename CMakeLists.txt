cmake_minimum_required(VERSION 3.12)

# Set the project name and version
project(AttacKit VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# set(PCAP_ROOT ${CMAKE_SOURCE_DIR}/thirdparty/npcap-sdk-1.15)


include(CTest)
enable_testing()

# Disable warnings caused by third party code
add_compile_options(
    -Wvla 
    -Wno-error=vla
    -Wno-inconsistent-missing-override
    -Wno-implicit-exception-spec-mismatch
)



# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src/core)
add_subdirectory(src/cli)
