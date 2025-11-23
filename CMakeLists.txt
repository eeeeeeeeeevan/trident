cmake_minimum_required(VERSION 3.10)
project(trident VERSION 0.6.7 LANGUAGES C)

find_package(OpenSSL REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(HASH_DIR ${CMAKE_SOURCE_DIR}/hash)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)

include_directories(${INCLUDE_DIR} ${HASH_DIR} ${SRC_DIR})

file(GLOB_RECURSE ALL_SRC CONFIGURE_DEPENDS
    "${SRC_DIR}/*.c"
    "${HASH_DIR}/*.c"
)

set(LIB_SOURCES ${ALL_SRC})
list(REMOVE_ITEM LIB_SOURCES "${SRC_DIR}/main.c")

add_library(tridlib STATIC ${LIB_SOURCES})
target_compile_options(tridlib PRIVATE -Wall -O2)
target_include_directories(tridlib PUBLIC ${INCLUDE_DIR} ${HASH_DIR})
target_link_libraries(tridlib PUBLIC OpenSSL::Crypto)
add_executable(trident "${SRC_DIR}/main.c")
target_compile_options(trident PRIVATE -Wall -O2)
target_include_directories(trident PRIVATE ${INCLUDE_DIR} ${HASH_DIR})
target_link_libraries(trident PRIVATE tridlib m)

option(BUILD_TESTS "builder opt" ON)
if(BUILD_TESTS)
  if(EXISTS "${CMAKE_SOURCE_DIR}/trident/trident_test.c")
    add_executable(trident_test "${CMAKE_SOURCE_DIR}/trident/trident_test.c")
    target_include_directories(trident_test PRIVATE ${INCLUDE_DIR} ${HASH_DIR} ${CMAKE_SOURCE_DIR}/trident)
    target_link_libraries(trident_test PRIVATE tridlib m)
    target_compile_options(trident_test PRIVATE -Wall -O2)
  endif()
endif()

install(TARGETS trident tridlib
        ARCHIVE DESTINATION lib)

set_target_properties(tridlib trident PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
