set(SOURCES
    src/arp_poisoning/arp_poisoning.cpp
    src/arp_poisoning/create_packet.cpp
    src/network_scout/network_scout.cpp
)

add_library(core STATIC ${SOURCES})

target_include_directories(core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/internal/
    # Include other third-party directories as needed
)

add_subdirectory(
    ${CMAKE_SOURCE_DIR}/thirdparty/PcapPlusPlus thirdparty/PcapPlusPlus
)

target_compile_options(Common++ PRIVATE -w)
target_compile_options(Packet++ PRIVATE -w)
target_compile_options(Pcap++ PRIVATE -w)

# Link third-party dependencies
target_link_libraries(core PRIVATE
    Common++
    Packet++
    Pcap++
    # other third-party dependencies
)
