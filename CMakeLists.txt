cmake_minimum_required(VERSION 3.20)
project(patty VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Dependencies via FetchContent ---
include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.4.2
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(nlohmann_json cli11)

# --- Library: patty ---
set(PATTY_SOURCES
    src/core/pattern.cpp
    src/core/scanner.cpp
    src/memory/file.cpp
    src/target/loader.cpp
)

# Platform-specific sources
if(WIN32)
    list(APPEND PATTY_SOURCES src/memory/process_win.cpp)
endif()

add_library(patty_lib STATIC ${PATTY_SOURCES})
target_include_directories(patty_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(patty_lib PUBLIC nlohmann_json::nlohmann_json)

if(WIN32)
    target_link_libraries(patty_lib PUBLIC psapi)
endif()

# Enable warnings
if(MSVC)
    target_compile_options(patty_lib PRIVATE /W4)
else()
    target_compile_options(patty_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

# --- CLI: patty ---
add_executable(patty cli/main.cpp)
target_link_libraries(patty PRIVATE patty_lib CLI11::CLI11)

if(MSVC)
    target_compile_options(patty PRIVATE /W4)
else()
    target_compile_options(patty PRIVATE -Wall -Wextra -Wpedantic)
endif()

# --- Install ---
install(TARGETS patty_lib patty
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/patty DESTINATION include)

# --- Tests (optional) ---
option(PATTY_BUILD_TESTS "Build tests" ON)
if(PATTY_BUILD_TESTS)
    enable_testing()

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
        GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(patty_tests
        tests/test_pattern.cpp
        tests/test_scanner.cpp
        tests/test_providers.cpp
    )
    target_link_libraries(patty_tests PRIVATE patty_lib GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(patty_tests)
endif()
