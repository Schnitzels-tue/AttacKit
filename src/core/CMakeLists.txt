# Specify the sources for the logger static library
set(SOURCES
    core.cpp
)

# Declare the logger as a static library
add_library(core STATIC ${SOURCES})

# Add PcapPlusPlus subdirectory
add_subdirectory(
    ${CMAKE_SOURCE_DIR}/thirdparty/PcapPlusPlus thirdparty/PcapPlusPlus
)

# Link third-party dependencies
target_link_libraries(core PRIVATE
    Common++
    Packet++
    Pcap++
    # other third-party dependencies
)

# Include directories for the logger
target_include_directories(core PRIVATE
    ${CMAKE_SOURCE_DIR}/include/core
    # Include other third-party directories as needed
)
