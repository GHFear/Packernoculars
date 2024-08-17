#pragma once


struct DOS_HEADER {                         // DOS .EXE header
    uint16_t   e_magic;                     // Magic number
    uint16_t   e_cblp;                      // Bytes on last page of file
    uint16_t   e_cp;                        // Pages in file
    uint16_t   e_crlc;                      // Relocations
    uint16_t   e_cparhdr;                   // Size of header in paragraphs
    uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
    uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
    uint16_t   e_ss;                        // Initial (relative) SS value
    uint16_t   e_sp;                        // Initial SP value
    uint16_t   e_csum;                      // Checksum
    uint16_t   e_ip;                        // Initial IP value
    uint16_t   e_cs;                        // Initial (relative) CS value
    uint16_t   e_lfarlc;                    // File address of relocation table
    uint16_t   e_ovno;                      // Overlay number
    uint16_t   e_res[4];                    // Reserved words
    uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
    uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
    uint16_t   e_res2[10];                  // Reserved words
    int32_t   e_lfanew;                    // File address of new exe header
};

struct FILE_HEADER {
    uint16_t    Machine;
    uint16_t    NumberOfSections;
    uint32_t   TimeDateStamp;
    uint32_t   PointerToSymbolTable;
    uint32_t   NumberOfSymbols;
    uint16_t    SizeOfOptionalHeader;
    uint16_t    Characteristics;
};

struct DATA_DIRECTORY {
    uint32_t   VirtualAddress;
    uint32_t   Size;
};

struct OPTIONAL_HEADER64 {
    uint16_t        Magic;
    uint8_t        MajorLinkerVersion;
    uint8_t        MinorLinkerVersion;
    uint32_t       SizeOfCode;
    uint32_t       SizeOfInitializedData;
    uint32_t       SizeOfUninitializedData;
    uint32_t       AddressOfEntryPoint;
    uint32_t       BaseOfCode;
    uint64_t   ImageBase;
    uint32_t       SectionAlignment;
    uint32_t       FileAlignment;
    uint16_t        MajorOperatingSystemVersion;
    uint16_t        MinorOperatingSystemVersion;
    uint16_t        MajorImageVersion;
    uint16_t        MinorImageVersion;
    uint16_t        MajorSubsystemVersion;
    uint16_t        MinorSubsystemVersion;
    uint32_t       Win32VersionValue;
    uint32_t       SizeOfImage;
    uint32_t       SizeOfHeaders;
    uint32_t       CheckSum;
    uint16_t        Subsystem;
    uint16_t        DllCharacteristics;
    uint64_t   SizeOfStackReserve;
    uint64_t   SizeOfStackCommit;
    uint64_t   SizeOfHeapReserve;
    uint64_t   SizeOfHeapCommit;
    uint32_t       LoaderFlags;
    uint32_t       NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
};

struct NT_HEADERS64 {
    uint32_t Signature;
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER64 OptionalHeader;
};

struct SECTION_HEADER {
    uint8_t    Name[8];
    union {
        uint32_t   PhysicalAddress;
        uint32_t   VirtualSize;
    } Misc;
    uint32_t   VirtualAddress;
    uint32_t   SizeOfRawData;
    uint32_t   PointerToRawData;
    uint32_t   PointerToRelocations;
    uint32_t   PointerToLinenumbers;
    uint16_t    NumberOfRelocations;
    uint16_t    NumberOfLinenumbers;
    uint32_t   Characteristics;
};

struct IMPORT_BY_NAME {
    uint16_t    Hint;
    const char*   Name;
};

struct THUNK_DATA64 {
    union {
        uint64_t ForwarderString;  // PBYTE 
        uint64_t Function;         // PDWORD
        uint64_t Ordinal;
        uint64_t AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
};

struct Thunk_Collection64 {
    THUNK_DATA64 thunk_data64;
    IMPORT_BY_NAME import_by_name;
};

struct IMPORT_DESCRIPTOR {
    union {
        uint32_t   Characteristics;            // 0 for terminating null import descriptor
        uint32_t   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } import_desc_union;
    uint32_t   TimeDateStamp;                  // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)

    uint32_t   ForwarderChain;                 // -1 if no forwarders
    uint32_t   Name;
    uint32_t   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
};

struct EXPORT_COLLECTION {
    std::vector <uint32_t> FunctionRVA;
    std::vector <uint32_t> NameRVA;
    std::vector <uint16_t> NameOrdinalRVA;
};

struct EXPORT_DIRECTORY {
    uint32_t	Characteristics;
    uint32_t	TimeDateStamp;
    uint16_t	MajorVersion;
    uint16_t	MinorVersion;
    uint32_t	Name;
    uint32_t	Base;
    uint32_t	NumberOfFunctions;
    uint32_t	NumberOfNames;
    uint32_t	AddressOfFunctions;
    uint32_t	AddressOfNames;
    uint32_t	AddressOfNameOrdinals;
};

struct BASE_RELOCATION
{
    uint32_t	            VirtualAddress;
    uint32_t	            SizeOfBlock;
    std::vector<uint16_t>	    TypeOffset;
};

struct RELOCATION
{
    union {
        uint32_t   VirtualAddress;
        uint32_t   RelocCount;
    } reloc_union;
    uint32_t   SymbolTableIndex;
    uint16_t    Type;
};

#define SIZEOF_RELOCATION 10

struct DELAYLOAD_DESCRIPTOR
{
    union
    {
        uint32_t AllAttributes;
        struct
        {
            uint32_t RvaBased : 1;
            uint32_t ReservedAttributes : 31;
        } delayed_union;
    } Attributes;

    uint32_t DllNameRVA;
    uint32_t ModuleHandleRVA;
    uint32_t ImportAddressTableRVA;
    uint32_t ImportNameTableRVA;
    uint32_t BoundImportAddressTableRVA;
    uint32_t UnloadInformationTableRVA;
    uint32_t TimeDateStamp;
};

struct PE_DATABASE {
    DOS_HEADER* dos_header = nullptr;
    NT_HEADERS64* nt_headers = nullptr;
    std::vector<SECTION_HEADER*> section_header;
    std::vector<IMPORT_DESCRIPTOR*> import_descriptor;
    std::vector<std::vector<Thunk_Collection64>> import_thunk_collection;
    EXPORT_DIRECTORY* export_directory = nullptr;
    EXPORT_COLLECTION export_thunk_collection;
    std::vector<DELAYLOAD_DESCRIPTOR*> delayed_imports_descriptor;
    std::vector<BASE_RELOCATION*> base_relocations;
};