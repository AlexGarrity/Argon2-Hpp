cmake_minimum_required(VERSION 3.24)
project(
  argon2-hpp
  VERSION 1.0.0
  LANGUAGES C CXX)

include(FetchContent)
include(GNUInstallDirs)

FetchContent_Declare(
  argon2
  GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
  GIT_TAG master
  GIT_SHALLOW true)

FetchContent_MakeAvailable(argon2)

add_library(argon2-hpp)
add_library(Argon2::Argon2-Hpp ALIAS argon2-hpp)

target_sources(
  argon2-hpp
  PRIVATE ${argon2_SOURCE_DIR}/src/blake2/blake2b.c
          ${argon2_SOURCE_DIR}/src/argon2.c
          ${argon2_SOURCE_DIR}/src/core.c
          ${argon2_SOURCE_DIR}/src/encoding.c
          ${argon2_SOURCE_DIR}/src/opt.c
          ${argon2_SOURCE_DIR}/src/thread.c
          ${CMAKE_CURRENT_SOURCE_DIR}/src/Argon2/Argon2.cpp)

target_include_directories(
  argon2-hpp
  PRIVATE ${argon2_SOURCE_DIR}/src ${argon2_SOURCE_DIR}/include
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(argon2-hpp PROPERTIES VERSION 0.1.0 SOVERSION 0)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  enable_testing()
  add_subdirectory(tests)
endif()

install(
  TARGETS argon2-hpp
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/Argon2/Argon2.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Argon2)
