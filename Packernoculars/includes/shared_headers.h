#pragma once
#pragma warning(disable:4996)
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#elif _WIN64
#include <Windows.h>
#endif
#include <thread>
#include <chrono>
#include <string>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <map>
// Redirect C output (fprintf) to a file
FILE* cFile = nullptr;
#include "pe_structs.h"
#include "tools.h"
#include "print_structs.h"
#include "print_tools.h"
#include "packer_detector.h"
#include "program_handlers.h"
#include "create_database.h"
#include "lambdas.h"