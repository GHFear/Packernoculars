#pragma once

bool find_packer_type_simple(PE_DATABASE* database)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	try
	{
		for (int i = 0; i < database->section_header.size(); i++)
		{
			if (strcmp((const char*)database->section_header[i]->Name, ".ace\0\0\0") == false)
			{
				SetConsoleTextAttribute(hConsole, 10);
				printf("\nPacked with AntiCheatExpert.\n\n");
				SetConsoleTextAttribute(hConsole, 15);
				return true;
			}
			else if (strcmp((const char*)database->section_header[i]->Name,".ncg0\0\0") == false)
			{
				SetConsoleTextAttribute(hConsole, 10);
				printf("\nPacked with nProtect Game Guard.\n\n");
				SetConsoleTextAttribute(hConsole, 15);
				return true;
			}
			else if (strcmp((const char*)database->section_header[i]->Name, ".bind\0\0") == false)
			{
				SetConsoleTextAttribute(hConsole, 10);
				printf("\nPacked with SteamStub DRM.\n\n");
				SetConsoleTextAttribute(hConsole, 15);
				return true;
			}
			else if (strcmp((const char*)database->section_header[i]->Name, ".theia\0") == false)
			{
				SetConsoleTextAttribute(hConsole, 10);
				printf("\nPacked with Theia.\n\n");
				SetConsoleTextAttribute(hConsole, 15);
				return true;
			}
			else if (
				strcmp((const char*)database->section_header[i]->Name, ".xpdata") == false || 
				strcmp((const char*)database->section_header[i]->Name, ".trace\0") == false || 
				strcmp((const char*)database->section_header[i]->Name, ".link\0\0") == false || 
				strcmp((const char*)database->section_header[i]->Name, ".xtext\0") == false ||
				strcmp((const char*)database->section_header[i]->Name, ".xcode\0") == false ||
				strcmp((const char*)database->section_header[i]->Name, ".00cfg\0") == false
				)
			{
				SetConsoleTextAttribute(hConsole, 10);
				printf("\nPacked with Denuvo.\n\n");
				SetConsoleTextAttribute(hConsole, 15);
				return true;
			}
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	SetConsoleTextAttribute(hConsole, 10);
	printf("\nPacked with Unknown Packer or Unpacked.\n\n");
	SetConsoleTextAttribute(hConsole, 15);
	return true;
};