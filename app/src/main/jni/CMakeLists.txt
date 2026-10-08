cmake_minimum_required(VERSION 3.22)
project(dfroot)
enable_language(ASM)

set(JNI_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Use include_directories() rather than splicing -I into the flags: CMake then
# quotes the path per compiler invocation. A raw "-I${JNI_DIR}" broke when the
# project lived under a path with a space (e.g. ".../Android Project/..."),
# because the flag got split into two arguments.
include_directories("${JNI_DIR}")

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${C_FLAGS} -Wall -Wextra -fno-stack-protector -fomit-frame-pointer")

set(SPLICEHELPER "${JNI_DIR}/splicehelper")
add_custom_command(
    OUTPUT "${SPLICEHELPER}"
    COMMAND "${CMAKE_C_COMPILER}"
            --target=${CMAKE_C_COMPILER_TARGET}
            --sysroot=${CMAKE_SYSROOT}
            "${JNI_DIR}/splicehelper.c"
            -o "${SPLICEHELPER}"
            -nodefaultlibs -nostartfiles -ffreestanding -static
    COMMAND "${CMAKE_STRIP}" "${SPLICEHELPER}"
    DEPENDS "${JNI_DIR}/splicehelper.c"
    COMMENT "Building splicehelper"
)
add_custom_target(splicehelper_bin DEPENDS "${SPLICEHELPER}")

# --- Bundled-KMI manifest: the single source of truth, shared with the
# Makefile, .github/workflows/build.yml and MainActivity.java. One
# "android<rel>-<major>.<minor>" per line; blank lines and '#' comments are
# ignored.
set(KMI_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/../assets/kmis.txt")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${KMI_MANIFEST}")

file(STRINGS "${KMI_MANIFEST}" KMI_MANIFEST_LINES)
set(KMIS "")
foreach(line IN LISTS KMI_MANIFEST_LINES)
    string(STRIP "${line}" line)
    if(line MATCHES "^android[0-9]+-[0-9]+\\.[0-9]+$")
        list(APPEND KMIS "${line}")
    endif()
endforeach()
if(NOT KMIS)
    message(FATAL_ERROR "No KMIs parsed from ${KMI_MANIFEST}")
endif()

set(KO_FILES "")
foreach(kmi IN LISTS KMIS)
    list(APPEND KO_FILES "${JNI_DIR}/ko/dfroot-${kmi}.ko")
endforeach()

# Guard: exp.c embeds the modules by hand. Fail the build if its .incbin set or
# its select_ko_image() entry count drifts from the manifest, so we never ship
# an APK that bundles a module it can't select (or claims one it lacks).
file(READ "${JNI_DIR}/exp.c" EXP_C_SRC)
string(REGEX MATCHALL "dfroot-android[0-9]+-[0-9]+\\.[0-9]+\\.ko" EXP_INCBIN "${EXP_C_SRC}")
set(EXP_INCBIN_KMIS "")
foreach(f IN LISTS EXP_INCBIN)
    string(REGEX REPLACE "^dfroot-(.*)\\.ko$" "\\1" kmi "${f}")
    list(APPEND EXP_INCBIN_KMIS "${kmi}")
endforeach()
list(SORT KMIS)
list(SORT EXP_INCBIN_KMIS)
if(NOT KMIS STREQUAL EXP_INCBIN_KMIS)
    message(FATAL_ERROR
        "KMI manifest vs exp.c mismatch.\n"
        "  manifest (${KMI_MANIFEST}) : ${KMIS}\n"
        "  exp.c .incbin             : ${EXP_INCBIN_KMIS}\n"
        "Add/remove the module in both places (and its imgs[] entry).")
endif()
string(REGEX MATCHALL
       "dfroot_ko_[0-9]+_[0-9]+_[0-9]+_start,[ ]+dfroot_ko_[0-9]+_[0-9]+_[0-9]+_end[}]"
       EXP_IMGS "${EXP_C_SRC}")
list(LENGTH KMIS KMI_COUNT)
list(LENGTH EXP_IMGS IMGS_COUNT)
if(NOT KMI_COUNT EQUAL IMGS_COUNT)
    message(FATAL_ERROR
        "exp.c select_ko_image() has ${IMGS_COUNT} entries but the manifest lists ${KMI_COUNT} KMIs.")
endif()

# AGP only packages lib*.so, so the executable is named libdfroot.so and lands
# in the APK's native lib dir. The app execs it from nativeLibraryDir, which is
# executable (app data dir is not).
add_executable(dfroot exp.c libcxx.S elf_parser.c)
add_dependencies(dfroot splicehelper_bin)
set_target_properties(dfroot PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

set_source_files_properties(exp.c PROPERTIES
    OBJECT_DEPENDS "${KO_FILES};${SPLICEHELPER}")

target_link_libraries(dfroot log)
target_link_options(dfroot PRIVATE -Wl,-z,max-page-size=16384)

add_executable(bootstrap bootstrap.c dftty.c)
set_target_properties(bootstrap PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
target_link_options(bootstrap PRIVATE -Wl,-z,max-page-size=16384)

# Vendored Termux PTY shim: com.termux.terminal.JNI does
# System.loadLibrary("termux"), so the module must be named "termux".
add_library(termux SHARED termux.c)
target_link_options(termux PRIVATE -Wl,-z,max-page-size=16384)
