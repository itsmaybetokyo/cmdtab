cmake_minimum_required(VERSION 3.16)
project(cmdtab C)

set(C_STANDARD 99)
set(C_STANDARD_REQUIRED TRUE)

# Set default build type to MinSizeRel if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE MinSizeRel CACHE STRING "Build type" FORCE)
endif()

add_executable(cmdtab WIN32 "src/cmdtab.c" "res/cmdtab.rc")

# Statically link the C runtime to avoid redistributable dependencies
# This ensures the executable works without VCRUNTIME140.dll or UCRTBASE.dll
set_property(TARGET cmdtab PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# For Release builds, enable optimizations
if(CMAKE_BUILD_TYPE MATCHES "Release|MinSizeRel|RelWithDebInfo")
    target_compile_options(cmdtab PRIVATE /O2)
endif()

#set_property(TARGET ${PROJECT_NAME} PROPERTY
    #LINK_FLAGS /MANIFESTUAC:"level='highestAvailable' uiAccess='true'"
#)
#mt.exe -manifest "cmdtab.exe.manifest" -updateresource:"cmdtab.exe;"#1
#mt.exe -manifest "cmdtab.exe.manifest" -outputresource:"cmdtab.exe;"#1
