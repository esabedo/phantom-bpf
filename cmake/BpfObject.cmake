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

  set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
  set(VMLINUX_HEADER "${GENERATED_DIR}/vmlinux.h")
  set(BPF_OBJECT "${GENERATED_DIR}/${BPF_OUTPUT_BASENAME}.bpf.o")
  set(BPF_SKELETON "${GENERATED_DIR}/${BPF_OUTPUT_BASENAME}.skel.h")

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
      -D__TARGET_ARCH_x86
      -I"${GENERATED_DIR}"
      -I"${CMAKE_CURRENT_SOURCE_DIR}/include"
      -I/usr/include/x86_64-linux-gnu
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
