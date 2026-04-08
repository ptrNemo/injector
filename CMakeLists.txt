cmake_minimum_required(VERSION 4.2)
project(injector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(injector STATIC injector.cpp)

set_property(TARGET injector PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
target_compile_definitions(injector PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
