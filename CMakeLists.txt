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

add_bpf_object(
  TARGET phantom_http_bpf
  SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/phantom_http.bpf.c"
  OUTPUT_BASENAME phantom_http
)

add_executable(phantom-agent
  src/agent/main.cpp
)

target_include_directories(phantom-agent
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

add_dependencies(phantom-agent phantom_http_bpf_skeleton)

target_link_libraries(phantom-agent
  PRIVATE
    PkgConfig::LIBBPF
    Threads::Threads
)

target_compile_options(phantom-agent PRIVATE
  -Wall
  -Wextra
  -Wpedantic
)

install(TARGETS phantom-agent RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
