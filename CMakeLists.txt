cmake_minimum_required(VERSION 3.16)
project(mksprdpac C)

set(CMAKE_C_STANDARD 99)

add_compile_options(-Wall -Wextra)

add_executable(mksprdpac main.c)