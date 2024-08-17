#pragma once


void* add_base_offset(void* exe_base, uint64_t offset)
{
	return static_cast<char*>(exe_base) + offset;
}

void* add_base_offset_rva(void* exe_base, uint64_t offset, uint64_t rva)
{
	return static_cast<char*>(exe_base) + offset - rva;
}

uint32_t get_disk_rva_translation(PE_DATABASE* database, uint8_t directory_index)
{
    if (database->nt_headers->FileHeader.NumberOfSections == 0) return -1;

    const uint32_t import_directory_va = database->nt_headers->OptionalHeader.DataDirectory[directory_index].VirtualAddress;

    for (int i = 0; i < database->nt_headers->FileHeader.NumberOfSections; i++)
    {
        const uint32_t section_start_virtual = database->section_header[i]->VirtualAddress;
        const uint32_t section_end_virtual = section_start_virtual + database->section_header[i]->Misc.VirtualSize;
        const uint32_t pointer_to_raw_data = database->section_header[i]->PointerToRawData;

        if (section_start_virtual <= import_directory_va && section_end_virtual >= import_directory_va)
            return section_start_virtual - pointer_to_raw_data;
    }

    return -1;
}