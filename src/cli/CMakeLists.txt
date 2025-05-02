# Add source files
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
    src/cli/*.cpp
)

add_executable(${CMAKE_PROJECT_NAME} cli.cpp)

# Link the libraries to the executable
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
    core
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include/cli
    ${CMAKE_SOURCE_DIR}/include/core
)
