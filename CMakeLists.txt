cmake_minimum_required(VERSION 3.23)
project(shitsunya)

set(CMAKE_CXX_STANDARD 23)

file(GLOB_RECURSE SOURCE_FILES "src/**.cpp" "src/**.hpp" "src/*.h")

add_executable(shitsunya ${SOURCE_FILES})

# set(CMAKE_TOOLCHAIN_FILE ${CMAKE_TOOLCHAIN_FILE})
# log toolchain file
message(STATUS "CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")


find_package(asio CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS container)
find_package(spdlog CONFIG REQUIRED)

target_link_libraries(shitsunya PUBLIC
        asio asio::asio
        # nlohmann_json::nlohmann_json
        Boost::container
        spdlog::spdlog_header_only
        )

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # target_link_libraries(shitsunya PRIVATE pthread)
    # add_compile_options(-pthread)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif ()

# add_library(test_shitsu STATIC ${SOURCE_FILES})

add_subdirectory(./test)
