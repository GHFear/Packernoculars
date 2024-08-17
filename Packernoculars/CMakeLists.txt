cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(Packernoculars VERSION 0.1.2)
include_directories(includes)
add_executable(
Packernoculars
Packernoculars.cpp
includes/shared_headers.h
includes/create_database.h
includes/pe_structs.h
includes/packer_detector.h
includes/print_structs.h
includes/print_tools.h
includes/program_handlers.h
includes/terminal_handler.h
includes/tools.h
includes/lambdas.h
)
