#pragma once

bool print_dos_header(PE_DATABASE* database)
{
	try
	{
		fprintf(cFile,"--( DOS HEADER )--\n");
		fprintf(cFile,"  *--Magic number: %04X\n", database->dos_header->e_magic);
		fprintf(cFile,"  *--Bytes on last page of file: %04X\n", database->dos_header->e_cblp);
		fprintf(cFile,"  *--Pages in file: %04X\n", database->dos_header->e_cp);
		fprintf(cFile,"  *--Relocations: %04X\n", database->dos_header->e_crlc);
		fprintf(cFile,"  *--Size of header in paragraphs: %04X\n", database->dos_header->e_cparhdr);
		fprintf(cFile,"  *--Minimum extra paragraphs needed: %04X\n", database->dos_header->e_minalloc);
		fprintf(cFile,"  *--Maximum extra paragraphs needed: %04X\n", database->dos_header->e_maxalloc);
		fprintf(cFile,"  *--Initial (relative) SS value: %04X\n", database->dos_header->e_ss);
		fprintf(cFile,"  *--Initial SP value: %04X\n", database->dos_header->e_sp);
		fprintf(cFile,"  *--Checksum: %04X\n", database->dos_header->e_csum);
		fprintf(cFile,"  *--Initial IP value: %04X\n", database->dos_header->e_ip);
		fprintf(cFile,"  *--Initial (relative) CS value: %04X\n", database->dos_header->e_cs);
		fprintf(cFile,"  *--File address of relocation table: %04X\n", database->dos_header->e_lfarlc);
		fprintf(cFile,"  *--Overlay number: %04X\n", database->dos_header->e_ovno);
		for (int i = 0; i < 4; i++)
		{
			fprintf(cFile,"  *--Reserved words: %04X\n", database->dos_header->e_res[i]);
		}
		fprintf(cFile,"  *--OEM identifier: %04X\n", database->dos_header->e_oemid);
		fprintf(cFile,"  *--OEM information: %04X\n", database->dos_header->e_oeminfo);
		for (int i = 0; i < 10; i++)
		{
			fprintf(cFile,"  *--Reserved words: %04X\n", database->dos_header->e_res2[i]);
		}
		fprintf(cFile,"  *--File address of new exe header: %d\n\n", database->dos_header->e_lfanew);
	}
	catch (const std::exception&error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}
	
	return true;
};

bool print_nt_headers(PE_DATABASE* database)
{
	try
	{
		fprintf(cFile,"--( NT HEADERS64 )--\n");
		fprintf(cFile,"  *--Signature: %08X\n\n", database->nt_headers->Signature);
		fprintf(cFile,"--< FILE HEADER >--\n");
		fprintf(cFile,"  *--Machine: %04X\n", database->nt_headers->FileHeader.Machine);
		fprintf(cFile,"  *--NumberOfSections: %04X\n", database->nt_headers->FileHeader.NumberOfSections);
		fprintf(cFile,"  *--TimeDateStamp: %08X\n", database->nt_headers->FileHeader.TimeDateStamp);
		fprintf(cFile,"  *--PointerToSymbolTable: %08X\n", database->nt_headers->FileHeader.PointerToSymbolTable);
		fprintf(cFile,"  *--NumberOfSymbols: %08X\n", database->nt_headers->FileHeader.NumberOfSymbols);
		fprintf(cFile,"  *--SizeOfOptionalHeader: %04X\n", database->nt_headers->FileHeader.SizeOfOptionalHeader);
		fprintf(cFile,"  *--Characteristics: %04X\n\n", database->nt_headers->FileHeader.Characteristics);
		fprintf(cFile,"--< OPTIONAL HEADER64 >--\n");
		fprintf(cFile,"  *--Magic: %04X\n", database->nt_headers->OptionalHeader.Magic);
		fprintf(cFile,"  *--MajorLinkerVersion: %02X\n", database->nt_headers->OptionalHeader.MajorLinkerVersion);
		fprintf(cFile,"  *--MinorLinkerVersion: %02X\n", database->nt_headers->OptionalHeader.MinorLinkerVersion);
		fprintf(cFile,"  *--SizeOfCode: %08X\n", database->nt_headers->OptionalHeader.SizeOfCode);
		fprintf(cFile,"  *--SizeOfInitializedData: %08X\n", database->nt_headers->OptionalHeader.SizeOfInitializedData);
		fprintf(cFile,"  *--SizeOfUninitializedData: %08X\n", database->nt_headers->OptionalHeader.SizeOfUninitializedData);
		fprintf(cFile,"  *--AddressOfEntryPoint: %08X\n", database->nt_headers->OptionalHeader.AddressOfEntryPoint);
		fprintf(cFile,"  *--BaseOfCode: %08X\n", database->nt_headers->OptionalHeader.BaseOfCode);
		fprintf(cFile,"  *--ImageBase: %llu\n", database->nt_headers->OptionalHeader.ImageBase);
		fprintf(cFile,"  *--SectionAlignment: %08X\n", database->nt_headers->OptionalHeader.SectionAlignment);
		fprintf(cFile,"  *--FileAlignment: %08X\n", database->nt_headers->OptionalHeader.FileAlignment);
		fprintf(cFile,"  *--MajorOperatingSystemVersion: %04X\n", database->nt_headers->OptionalHeader.MajorOperatingSystemVersion);
		fprintf(cFile,"  *--MinorOperatingSystemVersion: %04X\n", database->nt_headers->OptionalHeader.MinorOperatingSystemVersion);
		fprintf(cFile,"  *--MajorImageVersion: %04X\n", database->nt_headers->OptionalHeader.MajorImageVersion);
		fprintf(cFile,"  *--MinorImageVersion: %04X\n", database->nt_headers->OptionalHeader.MinorImageVersion);
		fprintf(cFile,"  *--MajorSubsystemVersion: %04X\n", database->nt_headers->OptionalHeader.MajorSubsystemVersion);
		fprintf(cFile,"  *--MinorSubsystemVersion: %04X\n", database->nt_headers->OptionalHeader.MinorSubsystemVersion);
		fprintf(cFile,"  *--Win32VersionValue: %08X\n", database->nt_headers->OptionalHeader.Win32VersionValue);
		fprintf(cFile,"  *--SizeOfImage: %08X\n", database->nt_headers->OptionalHeader.SizeOfImage);
		fprintf(cFile,"  *--SizeOfHeaders: %08X\n", database->nt_headers->OptionalHeader.SizeOfHeaders);
		fprintf(cFile,"  *--CheckSum: %08X\n", database->nt_headers->OptionalHeader.CheckSum);
		fprintf(cFile,"  *--Subsystem: %04X\n", database->nt_headers->OptionalHeader.Subsystem);
		fprintf(cFile,"  *--DllCharacteristics: %04X\n", database->nt_headers->OptionalHeader.DllCharacteristics);
		fprintf(cFile,"  *--SizeOfStackReserve: %llu\n", database->nt_headers->OptionalHeader.SizeOfStackReserve);
		fprintf(cFile,"  *--SizeOfStackCommit: %llu\n", database->nt_headers->OptionalHeader.SizeOfStackCommit);
		fprintf(cFile,"  *--SizeOfHeapReserve: %llu\n", database->nt_headers->OptionalHeader.SizeOfHeapReserve);
		fprintf(cFile,"  *--SizeOfHeapCommit: %llu\n", database->nt_headers->OptionalHeader.SizeOfHeapCommit);
		fprintf(cFile,"  *--LoaderFlags: %08X\n", database->nt_headers->OptionalHeader.LoaderFlags);
		fprintf(cFile,"  *--NumberOfRvaAndSizes: %08X\n\n", database->nt_headers->OptionalHeader.NumberOfRvaAndSizes);
		fprintf(cFile,"--< Data Directories >--\n");
		for (int i = 0; i < 16; i++)
		{
			fprintf(cFile,"  *--Data Directory %d\n", i);
			fprintf(cFile,"     *--VirtualAddress: %08X\n", database->nt_headers->OptionalHeader.DataDirectory[i].VirtualAddress);
			fprintf(cFile,"     *--Size: %08X\n\n", database->nt_headers->OptionalHeader.DataDirectory[i].Size);
		}

		fprintf(cFile,"\n");
		
	}
	catch (const std::exception& error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}

	return true;
};

bool print_section_headers(PE_DATABASE* database)
{
	try
	{
		for (int i = 0; i < database->section_header.size(); i++)
		{
			fprintf(cFile,"--( SECTION HEADER %d )--\n", i);
			fprintf(cFile,"  *--Name: %s\n", database->section_header[i]->Name);
			fprintf(cFile,"  *--PhysicalAddress: %08X\n", database->section_header[i]->Misc.PhysicalAddress);
			fprintf(cFile,"  *--VirtualSize: %08X\n", database->section_header[i]->Misc.VirtualSize);
			fprintf(cFile,"  *--VirtualAddress: %08X\n", database->section_header[i]->VirtualAddress);
			fprintf(cFile,"  *--SizeOfRawData: %08X\n", database->section_header[i]->SizeOfRawData);
			fprintf(cFile,"  *--PointerToRawData: %08X\n", database->section_header[i]->PointerToRawData);
			fprintf(cFile,"  *--PointerToRelocations: %08X\n", database->section_header[i]->PointerToRelocations);
			fprintf(cFile,"  *--PointerToLinenumbers: %08X\n", database->section_header[i]->PointerToLinenumbers);
			fprintf(cFile,"  *--NumberOfRelocations: %04X\n", database->section_header[i]->NumberOfRelocations);
			fprintf(cFile,"  *--NumberOfLinenumbers: %04X\n", database->section_header[i]->NumberOfLinenumbers);
			fprintf(cFile,"  *--Characteristics: %08X\n\n", database->section_header[i]->Characteristics);
		}
	}
	catch (const std::exception& error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}

	return true;
};

bool print_import_descriptors(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database, 1);

		for (int i = 0; i < database->import_descriptor.size(); i++)
		{
			auto& importDesc = *database->import_descriptor[i];
			auto& thunkCollection = database->import_thunk_collection[i];
			auto dll_name_ptr = add_base_offset_rva(exe_base, importDesc.Name, rva_offset);

			fprintf(cFile,"--( IMPORT DESCRIPTOR %d )--\n", i);
			fprintf(cFile,"  *--Characteristics: %08X\n", importDesc.import_desc_union.Characteristics);
			fprintf(cFile,"  *--OriginalFirstThunk: %08X\n", importDesc.import_desc_union.OriginalFirstThunk);
			fprintf(cFile,"  *--TimeDateStamp: %08X\n", importDesc.TimeDateStamp);
			fprintf(cFile,"  *--ForwarderChain: %08X\n", importDesc.ForwarderChain);
			fprintf(cFile,"  *--Name: %s\n", (const char*)dll_name_ptr);
			fprintf(cFile,"  *--FirstThunk: %08X\n", importDesc.FirstThunk);
			fprintf(cFile,"  *--Functions:\n");

			for (int j = 0; j < thunkCollection.size(); j++)
			{

				fprintf(cFile,"     *--Function: %d\n", j);

				auto& thunkData = thunkCollection[j].thunk_data64;
				auto& importByName = thunkCollection[j].import_by_name;

				if ((thunkData.u1.Function & 0x8000000000000000) == 0x8000000000000000) //Is Ordinal
				{
					auto thunk_ordinal = thunkData.u1.Ordinal & 0xFFFF;
					fprintf(cFile,"     *--Ordinal: %llu\n\n", thunk_ordinal);
				}
				else //Is Name
				{
					fprintf(cFile,"     *--Name: %s\n", importByName.Name);
					fprintf(cFile,"     *--Hint: %04X\n\n", importByName.Hint);
				}
			}
		}
	}
	catch (const std::exception& error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}
	
	return true;
}

bool print_export_directory(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database, 0);
		auto& export_directory = *database->export_directory;
		auto export_name_ptr = add_base_offset_rva(exe_base, export_directory.Name, rva_offset);

		fprintf(cFile,"--( EXPORT DIRECTORY )--\n");
		fprintf(cFile,"  *--Characteristics: %08X\n", export_directory.Characteristics);
		fprintf(cFile,"  *--TimeDateStamp: %08X\n", export_directory.TimeDateStamp);
		fprintf(cFile,"  *--MajorVersion: %04X\n", export_directory.MajorVersion);
		fprintf(cFile,"  *--MinorVersion: %04X\n", export_directory.MinorVersion);
		fprintf(cFile,"  *--Name: %s\n", (const char*)export_name_ptr);
		fprintf(cFile,"  *--Base: %08X\n", export_directory.Base);
		fprintf(cFile,"  *--NumberOfFunctions: %u\n", export_directory.NumberOfFunctions);
		fprintf(cFile,"  *--NumberOfNames: %u\n", export_directory.NumberOfNames);
		fprintf(cFile,"  *--AddressOfFunctions: %08X\n", export_directory.AddressOfFunctions);
		fprintf(cFile,"  *--AddressOfNames: %08X\n", export_directory.AddressOfNames);
		fprintf(cFile,"  *--AddressOfNameOrdinals: %08X\n\n", export_directory.AddressOfNameOrdinals);

	}
	catch (const std::exception& error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}

	return true;
}

bool print_export_functions(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database, 0);
		auto export_function_collection = database->export_thunk_collection;

		fprintf(cFile,"--( EXPORT FUNCTION COLLECTION )--\n");
		for (size_t i = 0; i < database->export_directory->NumberOfFunctions; i++)
		{
			auto exported_function_name_ptr = add_base_offset_rva(exe_base, export_function_collection.NameRVA[i], rva_offset);
			fprintf(cFile,"  *--%s\n", (const char*)exported_function_name_ptr);
			fprintf(cFile,"  *--Function RVA: %08X\n", export_function_collection.FunctionRVA[i]);
			fprintf(cFile,"  *--Ordinal: %hu\n", export_function_collection.NameOrdinalRVA[i]);
			fprintf(cFile,"  *--Name RVA: %08X\n\n", export_function_collection.NameRVA[i]);
		}
	}
	catch (const std::exception& error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}

	return true;
}

bool print_delayed_import_descriptors(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database, 13);
		auto delayed_import_descriptors = database->delayed_imports_descriptor;

		fprintf(cFile,"--( DELAYED IMPORT DESCRIPTORS )--\n");
		for (size_t i = 0; i < database->delayed_imports_descriptor.size(); i++)
		{
			auto delayed_import_dll_name_ptr = add_base_offset_rva(exe_base, delayed_import_descriptors[i]->DllNameRVA, rva_offset);
			fprintf(cFile,"  *--%s\n", (const char*)delayed_import_dll_name_ptr);
			fprintf(cFile,"  *--Attributes: %u\n", delayed_import_descriptors[i]->Attributes.AllAttributes);
			fprintf(cFile,"  *--BoundImportAddressTableRVA: %08X\n", delayed_import_descriptors[i]->BoundImportAddressTableRVA);
			fprintf(cFile,"  *--DllNameRVA: %08X\n", delayed_import_descriptors[i]->DllNameRVA);
			fprintf(cFile,"  *--ImportAddressTableRVA: %08X\n", delayed_import_descriptors[i]->ImportAddressTableRVA);
			fprintf(cFile,"  *--ImportNameTableRVA: %08X\n", delayed_import_descriptors[i]->ImportNameTableRVA);
			fprintf(cFile,"  *--ModuleHandleRVA: %08X\n", delayed_import_descriptors[i]->ModuleHandleRVA);
			fprintf(cFile,"  *--TimeDateStamp: %08X\n", delayed_import_descriptors[i]->TimeDateStamp);
			fprintf(cFile,"  *--UnloadInformationTableRVA: %08X\n\n", delayed_import_descriptors[i]->UnloadInformationTableRVA);
		}
	}
	catch (const std::exception& error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}

	return true;
}

bool print_base_relocations(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database, 5);
		auto base_relocations = database->base_relocations;
		
		fprintf(cFile,"--( BASE RELOCATIONS )--\n");
		std::string relocation_concatenated_string = "";
		for (uint32_t i = 0; i < database->base_relocations.size(); i++)
		{
			relocation_concatenated_string += ("  *--Relocation: " + std::to_string(i) + "\n");
			relocation_concatenated_string += ("  *--PageVirtualAddress: " + std::to_string(base_relocations[i]->VirtualAddress) + "\n");
			relocation_concatenated_string += ("  *--SizeOfBlock: " + std::to_string(base_relocations[i]->SizeOfBlock) + "\n");

			for (uint32_t j = 0; j < base_relocations[i]->TypeOffset.size(); j++)
			{
				relocation_concatenated_string += ("    *--TypeOffset: " + std::to_string(base_relocations[i]->TypeOffset[j]) + "\n");
			}
			relocation_concatenated_string += "\n";
		}
		fprintf(cFile,"%s\n", relocation_concatenated_string.c_str());
	}
	catch (const std::exception& error)
	{
		fprintf(cFile,"%s\n", error.what());
		return false;
	}

	return true;
}