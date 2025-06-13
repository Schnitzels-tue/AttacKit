set(SOURCES
    src/arp_poisoning/all_out.cpp
    src/arp_poisoning/public.cpp
    src/arp_poisoning/silent.cpp
    src/dns_poisoning/all_out.cpp
    src/dns_poisoning/public.cpp
    src/dns_poisoning/silent.cpp
    src/ssl_stripping/silent.cpp
    src/ssl_stripping/public.cpp
    src/ssl_stripping/all_out.cpp
    src/network_scout/network_scout.cpp
    src/network_scout/sniffing.cpp
    src/common/pcap_to_common.cpp
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

if(WIN32)
    include_directories(${CMAKE_SOURCE_DIR}/thirdparty/boost-sdk)
else()
    find_package(Boost REQUIRED COMPONENTS system)
endif()

find_package(OpenSSL REQUIRED)
target_include_directories(core PRIVATE ${OpenSSL_INCLUDE_DIR})

target_compile_options(Common++ PRIVATE -w)
target_compile_options(Packet++ PRIVATE -w)
target_compile_options(Pcap++ PRIVATE -w)

# Link third-party dependencies
target_link_libraries(core PRIVATE
    Common++
    Packet++
    Pcap++
    logger
    OpenSSL::SSL
    OpenSSL::Crypto
    # other third-party dependencies
)
