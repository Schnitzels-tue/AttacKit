# Add source files
set(SOURCES
    src/cli.cpp
    src/helper/CLIParser.cpp
    src/helper/CLIExecutor.cpp
)

add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})

# Link the libraries to the executable
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
    core
    logger
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/internal/
)
