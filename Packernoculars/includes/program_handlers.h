#pragma once

bool IsExe(const std::string& fileName)
{
    return fileName.size() >= 4 && fileName.compare(fileName.size() - 3, 3, "exe") == 0;
}

std::string GetNameWithoutExtensionFromFullPath(std::string full_path)
{
	size_t last_slash_idx = full_path.find_last_of("\\/");
	size_t period_idx = full_path.rfind(".");


	if (last_slash_idx != std::string::npos && period_idx > last_slash_idx) {
		return full_path.substr(last_slash_idx + 1, period_idx - last_slash_idx - 1);
	}

	return full_path.substr(last_slash_idx + 1);
}


#ifdef __linux__

void clean_exit(int exe_handle)
{
	if (exe_handle != -1) { close(exe_handle); }
	printf("Press any key to exit...\n");
	int pause = getchar();
	exit(1);
}

auto process_exe(const char* file_path)
{
	struct RESULT { int loadFile; void* exe_base; };

	int fd = open(file_path, O_RDONLY);
	if (fd == -1) {
		std::cerr << "Failed to open the file." << std::endl;
		return RESULT{ -1, nullptr };
	}

	struct stat file_info;
	if (fstat(fd, &file_info) == -1) {
		std::cerr << "Failed to get file size." << std::endl;
		close(fd);
		return RESULT{ -1, nullptr };
	}
	size_t file_size = file_info.st_size;

	void* file_data = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_data == MAP_FAILED) {
		std::cerr << "Failed to map the file into memory." << std::endl;
		close(fd);
		return RESULT{ -1, nullptr };
	}

	return RESULT{ fd, file_data };
};

std::string path_to_load(int argc, char* argv)
{
	if (argc < 1 || argc > 2) {
		printf("Input path is in the wrong format!\n");
		clean_exit(-1);
	}

	std::string path_input_W;

	if (argc == 1) {
		std::cout << "\nENTER AMD64 EXE PATH: ";
		std::getline(std::cin, path_input_W);
	}
	else {
		path_input_W = argv;
	}

	if (!IsExe(path_input_W) || !print_exe_to_load(path_input_W.c_str())) {
		clean_exit(-1);
	}

	return path_input_W;
}

#elif _WIN64

void clean_exit(HANDLE exe_handle)
{
	if (exe_handle != nullptr) { CloseHandle(exe_handle); }
	system("Pause");
	exit(1);
}

auto create_exe_buffer(void* exe_file_handle)
{
	LPVOID lpBuffer = nullptr;
	DWORD number_of_bytes_to_read = 0;
	struct result { LPVOID lpBuffer; DWORD number_of_bytes_to_read; };
	try
	{
		number_of_bytes_to_read = GetFileSize(exe_file_handle, NULL);
		lpBuffer = HeapAlloc(GetProcessHeap(), 0, number_of_bytes_to_read);
		printf("   *--Created %d number of bytes for exe data!\n", number_of_bytes_to_read);
	}
	catch (const std::exception& error)
	{
		printf("Error: { %s }", error.what());
		return result{ nullptr, 0 };
	}
	return result{ lpBuffer, number_of_bytes_to_read };
}

auto process_exe(const char* file_path)
{
	struct RESULT { HANDLE loadFile; void* exe_base; };
	HANDLE loadFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (loadFile == INVALID_HANDLE_VALUE)
		return RESULT{ loadFile, nullptr };

	auto exe_buffer = create_exe_buffer(loadFile);
	DWORD number_of_bytes_read = 0;

	if (exe_buffer.lpBuffer && ReadFile(loadFile, exe_buffer.lpBuffer, exe_buffer.number_of_bytes_to_read, &number_of_bytes_read, NULL))
		printf("   *--Loaded %d bytes from exe into exe_buffer.lpBuffer!\n", number_of_bytes_read);

	if (!exe_buffer.lpBuffer || number_of_bytes_read == 0)
	{
		printf("exebuffer-lpbuffer or number_of_bytes_read = 0.");
		return RESULT{ loadFile, nullptr };
	}
		

	return RESULT{ loadFile, exe_buffer.lpBuffer };
};


std::string path_to_load(int argc, char* argv)
{
	if (argc < 1 || argc > 2) {
		printf("Input path is in the wrong format!\n");
		clean_exit(nullptr);
	}

	std::string path_input_W;

	if (argc == 1) {
		std::cout << "\nENTER AMD64 EXE PATH: ";
		std::getline(std::cin, path_input_W);
	}
	else {
		path_input_W = argv;
	}

	if (!IsExe(path_input_W) || !print_exe_to_load(path_input_W.c_str())) {
		clean_exit(nullptr);
	}

	return path_input_W;
}

#endif

