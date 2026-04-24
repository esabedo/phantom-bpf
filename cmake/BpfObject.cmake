function(add_bpf_object)
  set(options)
  set(oneValueArgs TARGET SOURCE OUTPUT_BASENAME)
  set(multiValueArgs)
  cmake_parse_arguments(BPF "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(NOT BPF_TARGET OR NOT BPF_SOURCE OR NOT BPF_OUTPUT_BASENAME)
    message(FATAL_ERROR "add_bpf_object requires TARGET, SOURCE, and OUTPUT_BASENAME")
  endif()

  find_program(CLANG_EXECUTABLE clang REQUIRED)
  find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)

  if(BPFTOOL_EXECUTABLE STREQUAL "/usr/sbin/bpftool")
    file(GLOB BPFTOOL_CANDIDATES "/usr/lib/linux-tools/*/bpftool")
    list(SORT BPFTOOL_CANDIDATES ORDER DESCENDING)
    list(GET BPFTOOL_CANDIDATES 0 BPFTOOL_REAL_EXECUTABLE)
    if(BPFTOOL_REAL_EXECUTABLE)
      set(BPFTOOL_EXECUTABLE "${BPFTOOL_REAL_EXECUTABLE}")
    endif()
  endif()

  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    set(BPF_TARGET_ARCH x86)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(BPF_TARGET_ARCH arm64)
  else()
    message(FATAL_ERROR "Unsupported BPF target architecture: ${CMAKE_SYSTEM_PROCESSOR}")
  endif()

  set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
  set(VMLINUX_HEADER "${GENERATED_DIR}/vmlinux.h")
  set(BPF_OBJECT "${GENERATED_DIR}/${BPF_OUTPUT_BASENAME}.bpf.o")
  set(BPF_SKELETON "${GENERATED_DIR}/${BPF_OUTPUT_BASENAME}.skel.h")
  set(BPF_INCLUDE_FLAGS
    "-I${GENERATED_DIR}"
    "-I${CMAKE_CURRENT_SOURCE_DIR}/include"
  )

  if(CMAKE_LIBRARY_ARCHITECTURE AND EXISTS "/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
    list(APPEND BPF_INCLUDE_FLAGS "-I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
  endif()

  file(MAKE_DIRECTORY "${GENERATED_DIR}")

  add_custom_command(
    OUTPUT "${VMLINUX_HEADER}"
    COMMAND /bin/sh -c "${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}"
    DEPENDS "${BPFTOOL_EXECUTABLE}"
    COMMENT "Generating CO-RE vmlinux.h"
    VERBATIM
  )

  add_custom_command(
    OUTPUT "${BPF_OBJECT}"
    COMMAND "${CLANG_EXECUTABLE}"
      -g
      -O2
      -target bpf
      "-D__TARGET_ARCH_${BPF_TARGET_ARCH}"
      ${BPF_INCLUDE_FLAGS}
      -c "${BPF_SOURCE}"
      -o "${BPF_OBJECT}"
    DEPENDS "${BPF_SOURCE}" "${VMLINUX_HEADER}"
    COMMENT "Compiling ${BPF_SOURCE}"
    VERBATIM
  )

  add_custom_command(
    OUTPUT "${BPF_SKELETON}"
    COMMAND /bin/sh -c "${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_OBJECT} > ${BPF_SKELETON}"
    DEPENDS "${BPF_OBJECT}"
    COMMENT "Generating libbpf skeleton ${BPF_SKELETON}"
    VERBATIM
  )

  add_custom_target("${BPF_TARGET}" DEPENDS "${BPF_OBJECT}")
  add_custom_target("${BPF_TARGET}_skeleton" DEPENDS "${BPF_SKELETON}")

  set("${BPF_TARGET}_OBJECT" "${BPF_OBJECT}" PARENT_SCOPE)
  set("${BPF_TARGET}_SKELETON" "${BPF_SKELETON}" PARENT_SCOPE)
endfunction()
