cmake_minimum_required(VERSION 3.18)
project(Sentinel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_packages(CURL REQUIRED)
find_packages(Gumbo REQUIRED)

include_directories(
    ${CURL_INCLUDE_DIRS}
    ${GUMBO_INCLUDE_DIRS}
    src/core
)

add_library(core
    src/core/http_client.cpp
    src/core/discovery.cpp
    src/core/input_inventory.h
)

target_link_libraries(core
    ${CURL_LIBRARIES}
    ${GUMBO_LIBRARIES}
)

add_executable(sentinel
    src/main.cpp
)
target_link_libraries(sentinel core ${CURL_LIBRARIES} ${GUMBO_LIBRARIES})

