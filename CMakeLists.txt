cmake_minimum_required(VERSION 3.18)
project(Sentinel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(CURL REQUIRED)

include_directories(
    ${CURL_INCLUDE_DIRS}
    src/core
)

add_library(core
    src/core/http_client.cpp
)

target_link_libraries(core
    ${CURL_LIBRARIES}
)

add_executable(sentinel
    src/main.cpp
)
target_link_libraries(sentinel core ${CURL_LIBRARIES})


# Build the demo server app
add_subdirectory(apps/demo_server)

add_executable(reporter_stub tools/reporter_stub.cc)
target_include_directories(reporter_stub PRIVATE ${CMAKE_SOURCE_DIR}/third_party)
set_target_properties(reporter_stub PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
