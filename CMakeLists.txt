cmake_minimum_required(VERSION 3.12)

# Set the project name and version
project(AttacKit VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PCAP_ROOT ${CMAKE_SOURCE_DIR}/thirdparty/npcap-sdk)


include(CTest)
enable_testing()

# Disable warnings caused by third party code, temporary fix not sure how to disable library errors when compiling
add_compile_options(
    -Wvla
    -Wno-error=vla
    -Wno-deprecated-declarations
    -Wno-inconsistent-missing-override
    -Wno-implicit-exception-spec-mismatch
)

# Visual studio generates many warnings don't know why
if (MSVC)
    add_compile_options(
        -Wno-error=old-style-cast
        -Wno-error=error=c++98-compat
        -Wno-error=c++98-compat-pedantic
        -Wno-error=extra-semi
        -Wno-error=c99-extensions
        -Wno-error=sign-conversion
        -Wno-error=unused-macros
        -Wno-error=reserved-macro-identifier
        -Wno-error=suggest-destructor-override
        -Wno-error=nonportable-system-include-path
        -Wno-error=unused-parameter
        -Wno-error=shorten-64-to-32
        -Wno-error=implicit-int-conversion
        -Wno-error=switch-enum
        -Wno-error=documentation
        -Wno-error=missing-prototypes
        -Wno-error=deprecated-copy-with-user-provided-dtor
        -Wno-error=covered-switch-default
        -Wno-error=exit-time-destructors
        -Wno-error=suggest-override
        -Wno-error=undef
        -Wno-error=inconstisten-missing-destructor-override
        -Wno-error=cast-qual
        -Wno-error=cast-align
        -Wno-error=unknown-warning-option
        -Wno-error=global-constructors
        -Wno-error=unused-template
        -Wno-error=inconsistent-missing-destructor-override
        -Wno-error=documentation-unknown-command
        -Wno-error=tautological-unsigned-zero-compare
        -Wno-error=tautological-value-range-compare
        -Wno-error=float-conversion
        -Wno-error=shadow-field
        -Wno-error=shadow-field-in-constructor
        -Wno-error=documentation-pedantic
        -Wno-error=extra-semi-stmt
        -Wno-error=reserved-identifier
        -Wno-error=zero-as-null-pointer-constant
        -Wno-error=deprecated
        -Wno-error=implicit-int-float-conversion
        -Wno-error=date-time
        -Wno-error=shadow
        -Wno-error=unreachable-code-return
        -Wno-error=unreachable-code-break
)
endif()



# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(core)
add_subdirectory(cli)
