cmake_minimum_required(VERSION 3.16)

project(vpn_project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(include)

add_executable(vpn_core
    src/main.cpp
)

add_executable(vpn_server
    src/server.cpp
    src/crypto.cpp
    src/tun.cpp
)

target_link_libraries(vpn_server PRIVATE OpenSSL::Crypto)

add_executable(vpn_client
    src/client.cpp
    src/crypto.cpp
    src/tun.cpp
)

target_link_libraries(vpn_client PRIVATE OpenSSL::Crypto)

add_executable(tun_test
    src/tun_test.cpp
)

include(CTest)
if(BUILD_TESTING)
    add_executable(session_test tests/session_test.cpp src/crypto.cpp)
    target_link_libraries(session_test PRIVATE OpenSSL::Crypto)
    add_test(NAME session_packets COMMAND session_test)
endif()
