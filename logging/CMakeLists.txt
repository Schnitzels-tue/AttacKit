add_library(logger INTERFACE)

target_include_directories(logger
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
    # Include other third-party directories as needed
)


