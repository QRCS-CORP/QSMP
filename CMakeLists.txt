cmake_minimum_required(VERSION 3.15)

project(QSMS_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# QSMS Static Library
file(GLOB_RECURSE QSMS_SOURCES "Source/QSMS/*.c")
file(GLOB_RECURSE QSMS_HEADERS "Source/QSMS/*.h")

add_library(qsms STATIC ${QSMS_SOURCES} ${QSMS_HEADERS})
target_include_directories(qsms PUBLIC "Source/QSMS")
target_link_libraries(qsms PUBLIC qsc)

# QSMS SIMPLEX Client
file(GLOB_RECURSE QSMS_CLIENT_SOURCES "Source/Client/*.c")

add_executable(qsms_client ${QSMS_CLIENT_SOURCES})
target_include_directories(qsms_client PRIVATE "Source/Client")
target_link_libraries(qsms_client PRIVATE qsms)

# QSMP Simplex Server
file(GLOB_RECURSE QSMS_SERVER_SOURCES "Source/Server/*.c")

add_executable(qsms_server ${QSMS_SERVER_SOURCES})
target_include_directories(qsms_server PRIVATE "Source/Server")
target_link_libraries(qsms_server PRIVATE qsms)

# Warnings
foreach(target qsms qsms_client qsms_server)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
