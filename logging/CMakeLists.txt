add_library(logger INTERFACE)

target_include_directories(core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
    # Include other third-party directories as needed
)


