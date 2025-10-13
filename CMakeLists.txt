cmake_minimum_required(VERSION 3.18)
project(Sentinel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GUMBO REQUIRED gumbo)
find_package(CURL REQUIRED)

include_directories(
    ${CURL_INCLUDE_DIRS}
    ${GUMBO_INCLUDE_DIRS}
    src/core
)

add_library(core
    src/core/http_client.cpp
    src/core/crawler.cpp
)

target_link_libraries(core
    ${CURL_LIBRARIES}
    ${GUMBO_LIBRARIES}
)

add_executable(sentinel
    src/main.cpp
)
target_link_libraries(sentinel core ${CURL_LIBRARIES} ${GUMBO_LIBRARIES})

