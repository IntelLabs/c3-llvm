add_compiler_rt_component(c3)

set(C3_SOURCES
  c3runtime.c
  )

include_directories(..)
include_directories(${LLVM_MAIN_INCLUDE_DIR}/../../c3/include)

set(X86_64 x86_64)
set(C3_SUPPORTED_ARCH ${X86_64})

foreach(arch ${C3_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.c3
    STATIC
    ARCHS ${arch}
    SOURCES ${C3_SOURCES}
            $<TARGET_OBJECTS:RTInterception.${arch}>
    PARENT_TARGET c3)
endforeach()
