cmake_minimum_required(VERSION 3.20)
project(patty VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CMakePackageConfigHelpers)
include(FetchContent)
include(GNUInstallDirs)

option(BUILD_SHARED_LIBS "Build patty as a shared library" OFF)
option(PATTY_BUILD_CLI "Build the standalone patty CLI" ON)
option(PATTY_BUILD_TESTS "Build patty tests" ON)

set(PATTY_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/patty" CACHE STRING
    "Install path for patty CMake package files")
set(PATTY_PACKAGE_DIR "${CMAKE_CURRENT_BINARY_DIR}/cmake")
set(PATTY_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")

file(MAKE_DIRECTORY "${PATTY_PACKAGE_DIR}")
file(MAKE_DIRECTORY "${PATTY_GENERATED_INCLUDE_DIR}/patty")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/patty/version.h.in"
    "${PATTY_GENERATED_INCLUDE_DIR}/patty/version.h"
    @ONLY
)

function(patty_enable_warnings target_name)
    if(MSVC)
        target_compile_options("${target_name}" PRIVATE /W4)
    else()
        target_compile_options("${target_name}" PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

find_package(nlohmann_json 3.11.3 CONFIG QUIET)
if(nlohmann_json_FOUND)
    if(DEFINED nlohmann_json_INCLUDE_DIRS)
        set(PATTY_NLOHMANN_JSON_INCLUDE_DIRS "${nlohmann_json_INCLUDE_DIRS}")
    else()
        set(PATTY_NLOHMANN_JSON_TARGET nlohmann_json::nlohmann_json)
        if(NOT TARGET "${PATTY_NLOHMANN_JSON_TARGET}" AND TARGET nlohmann_json)
            set(PATTY_NLOHMANN_JSON_TARGET nlohmann_json)
        endif()
        get_target_property(PATTY_NLOHMANN_JSON_INCLUDE_DIRS "${PATTY_NLOHMANN_JSON_TARGET}" INTERFACE_INCLUDE_DIRECTORIES)
    endif()
else()
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE
        GIT_SUBMODULES ""
    )
    FetchContent_MakeAvailable(nlohmann_json)
    set(PATTY_NLOHMANN_JSON_INCLUDE_DIRS "${nlohmann_json_SOURCE_DIR}/include")
endif()

if(PATTY_BUILD_CLI)
    find_package(CLI11 2.4.2 CONFIG QUIET)
    if(NOT CLI11_FOUND)
        FetchContent_Declare(
            cli11
            GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
            GIT_TAG        v2.4.2
            GIT_SHALLOW    TRUE
            GIT_SUBMODULES ""
        )
        FetchContent_MakeAvailable(cli11)
    endif()
endif()

set(PATTY_SOURCES
    src/core/pattern.cpp
    src/core/scanner.cpp
    src/memory/file.cpp
    src/target/loader.cpp
)

if(WIN32)
    list(APPEND PATTY_SOURCES src/memory/process_win.cpp)
endif()

add_library(patty ${PATTY_SOURCES})
add_library(patty::patty ALIAS patty)
add_library(patty_lib ALIAS patty)

set_target_properties(patty PROPERTIES
    EXPORT_NAME patty
    VERSION "${PROJECT_VERSION}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)

if(WIN32 AND BUILD_SHARED_LIBS)
    set_target_properties(patty PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

target_compile_features(patty PUBLIC cxx_std_20)
target_include_directories(patty
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PATTY_GENERATED_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(patty SYSTEM PRIVATE "${PATTY_NLOHMANN_JSON_INCLUDE_DIRS}")

if(WIN32)
    target_link_libraries(patty PUBLIC psapi)
endif()

patty_enable_warnings(patty)

if(PATTY_BUILD_CLI)
    add_executable(patty_cli cli/main.cpp)
    set_target_properties(patty_cli PROPERTIES OUTPUT_NAME patty)
    target_compile_features(patty_cli PRIVATE cxx_std_20)
    target_include_directories(patty_cli SYSTEM PRIVATE "${PATTY_NLOHMANN_JSON_INCLUDE_DIRS}")
    target_link_libraries(patty_cli PRIVATE patty CLI11::CLI11)
    patty_enable_warnings(patty_cli)
endif()

write_basic_package_version_file(
    "${PATTY_PACKAGE_DIR}/pattyConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pattyConfig.cmake.in"
    "${PATTY_PACKAGE_DIR}/pattyConfig.cmake"
    COPYONLY
)

export(
    TARGETS patty
    FILE "${PATTY_PACKAGE_DIR}/pattyTargets.cmake"
    NAMESPACE patty::
)

install(TARGETS patty
    EXPORT pattyTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

if(PATTY_BUILD_CLI)
    install(TARGETS patty_cli
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    )
endif()

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/patty"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h"
)
install(FILES "${PATTY_GENERATED_INCLUDE_DIR}/patty/version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/patty"
)

install(EXPORT pattyTargets
    FILE pattyTargets.cmake
    NAMESPACE patty::
    DESTINATION "${PATTY_CMAKE_INSTALL_DIR}"
)
install(FILES
    "${PATTY_PACKAGE_DIR}/pattyConfig.cmake"
    "${PATTY_PACKAGE_DIR}/pattyConfigVersion.cmake"
    DESTINATION "${PATTY_CMAKE_INSTALL_DIR}"
)

if(PATTY_BUILD_TESTS)
    enable_testing()

    find_package(GTest 1.14.0 CONFIG QUIET)
    if(NOT GTest_FOUND)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG        v1.14.0
            GIT_SHALLOW    TRUE
            GIT_SUBMODULES ""
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    add_executable(patty_tests
        tests/test_pattern.cpp
        tests/test_scanner.cpp
        tests/test_providers.cpp
    )
    target_compile_features(patty_tests PRIVATE cxx_std_20)
    target_link_libraries(patty_tests PRIVATE patty GTest::gtest_main)
    patty_enable_warnings(patty_tests)

    include(GoogleTest)
    gtest_discover_tests(patty_tests)

    if(PATTY_BUILD_CLI)
        set(PATTY_SMOKE_FIXTURE "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/patty-smoke.bin")

        add_test(NAME patty_cli_scan_help COMMAND $<TARGET_FILE:patty_cli> scan --help)
        add_test(NAME patty_cli_scan_value_help COMMAND $<TARGET_FILE:patty_cli> scan-value --help)
        add_test(NAME patty_cli_probe_help COMMAND $<TARGET_FILE:patty_cli> probe --help)

        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            add_test(
                NAME patty_cli_json_smoke
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.py ${PATTY_SMOKE_FIXTURE} $<TARGET_FILE:patty_cli>
            )

            execute_process(
                COMMAND ${Python3_EXECUTABLE} -c "import fastmcp"
                RESULT_VARIABLE PATTY_HAS_FASTMCP
                OUTPUT_QUIET
                ERROR_QUIET
            )
            if(PATTY_HAS_FASTMCP EQUAL 0)
                add_test(
                    NAME patty_mcp_smoke
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/mcp_smoke.py ${PATTY_SMOKE_FIXTURE} $<TARGET_FILE:patty_cli>
                )
            endif()
        endif()
    endif()
endif()
