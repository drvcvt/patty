## Project
- Universal memory pattern scanner — library + CLI
- Stack: C++20, CMake, CLI11, GoogleTest, nlohmann/json
- Status: Active — string patterns, match filters, parallel scanning, process + file memory

## Architecture
- `include/patty/` — Public headers
- `src/core/pattern.cpp` — Pattern parsing and representation
- `src/core/scanner.cpp` — Pattern scanning engine
- `src/memory/file.cpp` — File-backed memory provider
- `src/memory/process_win.cpp` — Process memory provider (Windows, psapi)
- `src/target/loader.cpp` — Target loading (JSON target definitions)
- `cli/main.cpp` — CLI entry point (CLI11)
- `targets/` — Target definition files
- `mcp/` — MCP server integration
- `tests/` — GoogleTest test suite

## Build & Run
- Configure: `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release`
- Build: `cmake --build build`
- Test: `ctest --test-dir build`
- Lint: no linter configured (MSVC /W4 or -Wall -Wextra -Wpedantic enabled)

## Code Style
- C++20, `#pragma once`
- snake_case functions/variables, PascalCase types
- Warnings: /W4 (MSVC) or -Wall -Wextra -Wpedantic

## Git
- Branch: master
- Commit format: imperative ("Add string patterns...", "Initial release...")

## Session Rules
- After changes: build + run tests
- Commit messages: English, Conventional Commits
- Direct fixes without asking

## Don'ts
- No raw new/delete — RAII / smart pointers
- Don't break the public API in `include/patty/` without versioning
