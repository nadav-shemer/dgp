cmake_minimum_required(VERSION 3.9.4)
project(dgp VERSION 0.1.0)

#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION FALSE)

list(APPEND CMAKE_MODULE_PATH "/home/nadav/repos/cmake-modules")

include(CTest)
enable_testing()
set(CTEST_PARALLEL_LEVEL "4")

set(profiler OFF)
set(coverage OFF)
set(asan OFF)
set(customflag ON)

if(${coverage})
include(CodeCoverage)
append_coverage_compiler_flags()
endif()

add_executable(dgp-simple dgp-simple.c)
add_executable(genseed genseed.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
target_link_libraries(dgp-simple crypto)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++2a")

if(${profiler})
#cmake -DCMAKE_CXX_FLAGS=-pg -DCMAKE_EXE_LINKER_FLAGS=-pg -DCMAKE_SHARED_LINKER_FLAGS=-pg <SOURCE_DIR>
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
endif()


if(${asan})
add_compile_options(-fsanitize=address)
target_link_libraries(dgp-simple
  -fsanitize=address
)
endif()

if(${coverage})
setup_target_for_coverage_lcov(NAME lcov EXECUTABLE ctest)
endif()

if (${customflag})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
endif()

find_program (BASH_PROGRAM bash)
add_test(basic ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/tests/basic.sh)
