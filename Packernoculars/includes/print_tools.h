#pragma once

bool print_intro(const char* gh_disasm_version)
{
	try
	{

		std::cout << R"(
  _____           _                                    _                
 |  __ \         | |                                  | |               
 | |__) |_ _  ___| | _____ _ __ _ __   ___   ___ _   _| | __ _ _ __ ___ 
 |  ___/ _` |/ __| |/ / _ \ '__| '_ \ / _ \ / __| | | | |/ _` | '__/ __|
 | |  | (_| | (__|   <  __/ |  | | | | (_) | (__| |_| | | (_| | |  \__ \
 |_|   \__,_|\___|_|\_\___|_|  |_| |_|\___/ \___|\__,_|_|\__,_|_|  |___/
                                                                        
                                                                        )"; printf("%s", gh_disasm_version);

		std::cout << R"(
 ___ _    _   _   _ ___  ___  _____   __  ___  ___  ___ _______      ___   ___ ___ 
|_ _| |  | | | | | / __|/ _ \| _ \ \ / / / __|/ _ \| __|_   _\ \    / /_\ | _ \ __|
 | || |__| |_| |_| \__ \ (_) |   /\ V /  \__ \ (_) | _|  | |  \ \/\/ / _ \|   / _| 
|___|____|____\___/|___/\___/|_|_\ |_|   |___/\___/|_|   |_|   \_/\_/_/ \_\_|_\___|    
)";

	}
	catch (const std::exception& error)
	{
		printf("Error: { %s }", error.what()); return false;
	}
	return true;
}

bool print_exe_to_load(const char* file_path)
{
	try
	{
		printf("\n");
		printf("--(Load Information)--\n");
		printf("   *--Loading Executable: %s\n", file_path);
	}
	catch (const std::exception& error)
	{
		printf("Error: { %s }", error.what()); return false;
	}
	return true;
}