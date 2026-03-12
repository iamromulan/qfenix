cmake_minimum_required(VERSION 3.16)
project(qfenix-app VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(QFENIX_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

# ---- Generate version.h from git (same logic as Makefile) ----

execute_process(
    COMMAND git describe --always --tags
    WORKING_DIRECTORY ${QFENIX_DIR}
    OUTPUT_VARIABLE QFENIX_GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT QFENIX_GIT_VERSION)
    set(QFENIX_GIT_VERSION "unknown-version")
endif()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/version.h"
    "#define VERSION \"${QFENIX_GIT_VERSION}\"\n")

# ---- Find dependencies ----

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXML2 REQUIRED IMPORTED_TARGET libxml-2.0)
pkg_check_modules(LIBUSB REQUIRED IMPORTED_TARGET libusb-1.0)
find_package(wxWidgets REQUIRED COMPONENTS core base webview)
include(${wxWidgets_USE_FILE})

# ---- qfenix C sources (from parent directory, unmodified) ----

set(QFENIX_C_SRCS
    ${QFENIX_DIR}/firehose.c
    ${QFENIX_DIR}/firehose_op.c
    ${QFENIX_DIR}/io.c
    ${QFENIX_DIR}/qdl.c
    ${QFENIX_DIR}/sahara.c
    ${QFENIX_DIR}/util.c
    ${QFENIX_DIR}/patch.c
    ${QFENIX_DIR}/program.c
    ${QFENIX_DIR}/read.c
    ${QFENIX_DIR}/sha2.c
    ${QFENIX_DIR}/sim.c
    ${QFENIX_DIR}/ufs.c
    ${QFENIX_DIR}/usb.c
    ${QFENIX_DIR}/ux.c
    ${QFENIX_DIR}/oscompat.c
    ${QFENIX_DIR}/vip.c
    ${QFENIX_DIR}/sparse.c
    ${QFENIX_DIR}/gpt.c
    ${QFENIX_DIR}/diag_switch.c
    ${QFENIX_DIR}/md5.c
    ${QFENIX_DIR}/hdlc.c
    ${QFENIX_DIR}/diag.c
    ${QFENIX_DIR}/pcie.c
    ${QFENIX_DIR}/pdu.c
    ${QFENIX_DIR}/ucs2_utf8.c
    ${QFENIX_DIR}/at_port.c
    ${QFENIX_DIR}/atcmd.c
    ${QFENIX_DIR}/atconsole.c
)

if(APPLE)
    list(APPEND QFENIX_C_SRCS ${QFENIX_DIR}/qcseriald.c)
endif()

#
# Key trick: rename main() in qdl.c to qfenix_cli_main() at compile time.
# This lets our main.cpp provide the real main() that dispatches between
# CLI and GUI mode. No modifications to qfenix source files needed.
#
set_source_files_properties(${QFENIX_DIR}/qdl.c PROPERTIES
    COMPILE_DEFINITIONS "main=qfenix_cli_main"
)

# ---- GUI C++ sources ----

set(GUI_CXX_SRCS
    src/main.cpp
    src/MainFrame.cpp
    src/HomePanel.cpp
    src/OpsPanel.cpp
    src/PartitionPanel.cpp
    src/NVBrowserPanel.cpp
    src/ConsolePanel.cpp
    src/ProcessRunner.cpp
)

# ---- Single combined binary ----

set(ALL_SRCS ${QFENIX_C_SRCS} ${GUI_CXX_SRCS})

if(APPLE)
    add_executable(QFenix MACOSX_BUNDLE ${ALL_SRCS})
    set_target_properties(QFenix PROPERTIES
        OUTPUT_NAME "qfenix"
        MACOSX_BUNDLE_BUNDLE_NAME "QFenix"
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.iamromulan.qfenix"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    )
elseif(WIN32)
    add_executable(QFenix WIN32 ${ALL_SRCS})
    set_target_properties(QFenix PROPERTIES OUTPUT_NAME "qfenix")
else()
    add_executable(QFenix ${ALL_SRCS})
    set_target_properties(QFenix PROPERTIES OUTPUT_NAME "qfenix")
endif()

# Include paths: qfenix dir (for headers) + build dir (for version.h)
target_include_directories(QFenix PRIVATE
    ${QFENIX_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Link everything
target_link_libraries(QFenix PRIVATE
    PkgConfig::LIBXML2
    PkgConfig::LIBUSB
    ${wxWidgets_LIBRARIES}
)

target_compile_definitions(QFenix PRIVATE
    QFENIX_RESOURCES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/resources"
    QFENIX_VERSION="${PROJECT_VERSION}"
)

# Platform-specific flags
if(APPLE)
    target_compile_definitions(QFenix PRIVATE HAVE_QCSERIALD)
    target_link_libraries(QFenix PRIVATE
        "-framework IOKit"
        "-framework CoreFoundation"
        util
    )
elseif(WIN32)
    target_link_libraries(QFenix PRIVATE ws2_32 setupapi)
endif()

# C sources get C flags, C++ sources get C++ flags
set_source_files_properties(${QFENIX_C_SRCS} PROPERTIES
    COMPILE_OPTIONS "-O2;-Wall"
)

# ---- Bundle resources ----

set(QFENIX_RESOURCES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/resources")

# Copy resources to build dir (for development runs)
file(GLOB RESOURCE_FILES "${QFENIX_RESOURCES_DIR}/*")
foreach(RES_FILE ${RESOURCE_FILES})
    get_filename_component(RES_NAME ${RES_FILE} NAME)
    configure_file(${RES_FILE}
        ${CMAKE_CURRENT_BINARY_DIR}/resources/${RES_NAME} COPYONLY)
endforeach()

if(APPLE)
    # Copy resources into .app/Contents/Resources/
    add_custom_command(TARGET QFenix POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${QFENIX_RESOURCES_DIR}
            $<TARGET_BUNDLE_DIR:QFenix>/Contents/Resources
        COMMENT "Bundling resources into .app"
    )
else()
    # Linux/Windows: resources/ next to the binary
    add_custom_command(TARGET QFenix POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${QFENIX_RESOURCES_DIR}
            $<TARGET_FILE_DIR:QFenix>/resources
        COMMENT "Copying resources next to binary"
    )
endif()
