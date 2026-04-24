cmake_minimum_required(VERSION 3.22)

project(phantom_bpf VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "Phantom BPF currently supports Linux builds only")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(BpfObject)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

enable_testing()

add_bpf_object(
  TARGET phantom_http_bpf
  SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/phantom_http.bpf.c"
  OUTPUT_BASENAME phantom_http
)

add_library(phantom_agent_core
  src/agent/correlator.cpp
  src/agent/event.cpp
  src/agent/http_aggregator.cpp
  src/agent/json_exporter.cpp
  src/agent/pipeline.cpp
)

target_include_directories(phantom_agent_core
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(phantom_agent_core
  PUBLIC
    Threads::Threads
)

target_compile_options(phantom_agent_core PRIVATE
  -Wall
  -Wextra
  -Wpedantic
)

add_executable(phantom-agent
  src/agent/main.cpp
)

target_include_directories(phantom-agent
  PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

add_dependencies(phantom-agent phantom_http_bpf_skeleton)

target_link_libraries(phantom-agent
  PRIVATE
    phantom_agent_core
    PkgConfig::LIBBPF
)

target_compile_options(phantom-agent PRIVATE
  -Wall
  -Wextra
  -Wpedantic
)

add_executable(phantom-agent-tests
  tests/agent_core_tests.cpp
)

target_link_libraries(phantom-agent-tests
  PRIVATE
    phantom_agent_core
)

target_compile_options(phantom-agent-tests PRIVATE
  -Wall
  -Wextra
  -Wpedantic
)

add_test(NAME phantom-agent-tests COMMAND phantom-agent-tests)

install(TARGETS phantom-agent RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
