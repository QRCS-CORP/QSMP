cmake_minimum_required(VERSION 3.15)

project(QSMP_Complete C)

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

# QSMP Static Library
file(GLOB_RECURSE QSMP_SOURCES "Source/QSMP/*.c")
file(GLOB_RECURSE QSMP_HEADERS "Source/QSMP/include/*.h")

add_library(qsmp STATIC ${QSMP_SOURCES} ${QSMP_HEADERS})
target_include_directories(qsmp PUBLIC Source/QSMP)
target_link_libraries(qsmp PUBLIC qsc)

# QSMP SIMPLEX Client
file(GLOB_RECURSE QSMP_CLIENT_SOURCES "Source/Simplex/Client/*.c")

add_executable(qsmp_client ${QSMP_CLIENT_SOURCES})
target_include_directories(qsmp_client PRIVATE "Source/Simplex/Client")
target_link_libraries(qsmp_client PRIVATE qsmp)

# QSMP Simplex Server
file(GLOB_RECURSE QSMP_SERVER_SOURCES "Source/Simplex/Server/*.c")

add_executable(qsmp_server ${QSMP_SERVER_SOURCES})
target_include_directories(qsmp_server PRIVATE Source/Simplex/Server)
target_link_libraries(qsmp_server PRIVATE qsmp)

# QSMP Duplex Listener
file(GLOB_RECURSE QSMP_LISTENER_SOURCES "Source/Duplex/Listener/*.c")

add_executable(qsmp_listener ${QSMP_LISTENER_SOURCES})
target_include_directories(qsmp_listener PRIVATE Source/Duplex/Listener)
target_link_libraries(qsmp_listener PRIVATE qsmp)

# QSMP DUPLEX Sender
file(GLOB_RECURSE QSMP_SENDER_SOURCES "Source/Duplex/Sender/*.c")

add_executable(qsmp_sender ${QSMP_SENDER_SOURCES})
target_include_directories(qsmp_sender PRIVATE "Source/Duplex/Sender")
target_link_libraries(qsmp_sender PRIVATE qsmp)

# Warnings -Werror
foreach(target qsmp qsmp_client qsmp_server qsmp_listener qsmp_sender)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endforeach()
