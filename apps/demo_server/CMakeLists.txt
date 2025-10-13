cmake_minimum_required(VERSION 3.15)
project(demo_server CXX)

add_executable(demo_server
  main.cpp
)

target_include_directories(demo_server PRIVATE
  ${CMAKE_SOURCE_DIR}/third_party
)

find_package(Threads REQUIRED)
target_link_libraries(demo_server PRIVATE Threads::Threads)
set_property(TARGET demo_server PROPERTY CXX_STANDARD 17)
