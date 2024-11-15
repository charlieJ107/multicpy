cmake_minimum_required(VERSION 3.29)
project(multicpy)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_COMPILER "cl")
set(CMAKE_CXX_COMPILER "cl")

find_package(OpenSSL REQUIRED)

add_executable(multicpy
        src/main.cpp
        src/address_parser.cpp
        src/task_queue.cpp
        src/file_copier.cpp
        src/hash_verifier.cpp
        src/recovery_manager.cpp
        src/recovery_manager.hpp
)

target_link_libraries(multicpy OpenSSL::SSL OpenSSL::Crypto)