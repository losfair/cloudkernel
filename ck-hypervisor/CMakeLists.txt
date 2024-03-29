cmake_minimum_required(VERSION 3.3)
project(ck-hypervisor)

include_directories(include)
file(GLOB SOURCES "src/*.cpp")
file(GLOB SANDBOX_SOURCES "sandbox/*.cpp")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_COMPILER clang-9)
set(CMAKE_CXX_COMPILER clang++-9)
set(CMAKE_C_FLAGS "-Wall -g -O2")
set(CMAKE_CXX_FLAGS "-Wall -g -O2")

set_source_files_properties(${SOURCES} PROPERTIES COMPILE_FLAGS "-fPIC" )
set_source_files_properties(${SANDBOX_SOURCES} PROPERTIES COMPILE_FLAGS "-static" )

add_executable(ck-hypervisor ${SOURCES})
target_link_libraries(ck-hypervisor pthread)
set_target_properties(ck-hypervisor PROPERTIES LINK_FLAGS "-pie")

add_executable(ck-hypervisor-sandbox ${SANDBOX_SOURCES})
target_link_libraries(ck-hypervisor-sandbox seccomp)
set_target_properties(ck-hypervisor-sandbox PROPERTIES LINK_FLAGS "-static -Wl,-T ../sandbox.ld")
