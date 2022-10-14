cmake_minimum_required(VERSION 3.24)
project(
  argon2-hpp
  VERSION 1.0.0
  LANGUAGES C CXX)

include(FetchContent)
include(GNUInstallDirs)

# Get the Argon2 source code
FetchContent_Declare(
  argon2
  GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
  GIT_TAG master
  GIT_SHALLOW true)
FetchContent_MakeAvailable(argon2)

# Create the Argon2 reference library
add_library(argon2)
add_library(Argon2::Argon2 ALIAS argon2)
target_sources(
  argon2
  PRIVATE ${argon2_SOURCE_DIR}/src/blake2/blake2b.c
          ${argon2_SOURCE_DIR}/src/argon2.c
          ${argon2_SOURCE_DIR}/src/core.c
          ${argon2_SOURCE_DIR}/src/encoding.c
          ${argon2_SOURCE_DIR}/src/opt.c
          ${argon2_SOURCE_DIR}/src/thread.c)

target_include_directories(
  argon2
  PRIVATE ${argon2_SOURCE_DIR}/src
  PUBLIC ${argon2_SOURCE_DIR}/include)

# Create the Argon2-Hpp library
add_library(argon2-hpp)
add_library(Argon2::Argon2-Hpp ALIAS argon2-hpp)
target_sources(argon2-hpp
               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/Argon2/Argon2.cpp)

target_include_directories(argon2-hpp
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(argon2-hpp PUBLIC argon2)

set_target_properties(argon2-hpp PROPERTIES VERSION 1.0.0 SOVERSION 1)

# Enable testing if this is at the top of the source tree
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  enable_testing()
  add_subdirectory(tests)
endif()

# Install Argon2 reference
install(
  TARGETS argon2
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES ${argon2_SOURCE_DIR}/include/argon2.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install Argon2-Hpp
install(
  TARGETS argon2-hpp
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/Argon2/Argon2.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Argon2)
