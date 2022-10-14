set(CMAKE_CXX_STANDARD 14)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt
    ON
    CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(argon2-hpp-tests)
target_sources(argon2-hpp-tests PRIVATE TestArgon2-Hpp.cpp)
target_link_libraries(argon2-hpp-tests PRIVATE GTest::gtest_main
                                               Argon2::Argon2-Hpp)

include(GoogleTest)
enable_testing()
gtest_discover_tests(argon2-hpp-tests)
