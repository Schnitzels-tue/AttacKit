# Specify the sources for the logger static library
set(SOURCES
    src/arp_poisoning.cpp
)

# Declare the logger as a static library
add_library(core STATIC ${SOURCES})

target_include_directories(core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/internal/
    # Include other third-party directories as needed
)

get_directory_property(old_dir_compile_options COMPILE_OPTIONS)

add_compile_options(-w)

add_subdirectory(
    ${CMAKE_SOURCE_DIR}/thirdparty/PcapPlusPlus thirdparty/PcapPlusPlus
)

set_directory_properties(
    PROPERTIES COMPILE_OPTIONS "${old_dir_compile_options}"
)

# Link third-party dependencies
target_link_libraries(core PRIVATE
    Common++
    Packet++
    Pcap++
    # other third-party dependencies
)
