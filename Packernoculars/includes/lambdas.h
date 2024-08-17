#pragma once

#ifdef __linux__

bool start_pe_parser(PE_DATABASE* database, void* exe_base, int loadFile)
{
	auto dos_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!create_dos_header(database, exe_base)) { clean_exit(loadFile); }
		};

	auto nt_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!create_nt_headers(database, exe_base)) { clean_exit(loadFile); }
		};

	auto section_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!create_section_headers(database, exe_base)) { clean_exit(loadFile); }
		};

	auto import_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!create_import_descriptors(database, exe_base)) { clean_exit(loadFile); }
		};

	auto export_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!create_export_directory(database, exe_base)) { clean_exit(loadFile); }
		};

	auto delayed_import_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!create_delayed_import_descriptors(database, exe_base)) { clean_exit(loadFile); }
		};

	auto base_relocations_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!create_page_relocations(database, exe_base)) { clean_exit(loadFile); }
		};

	auto print_lambda = [](PE_DATABASE* database, void* exe_base, int loadFile) {
		if (!print_dos_header(database)) { clean_exit(loadFile); }
		if (!print_nt_headers(database)) { clean_exit(loadFile); }
		if (!print_section_headers(database)) { clean_exit(loadFile); }
		if (!print_import_descriptors(database, exe_base)) { clean_exit(loadFile); }
		if (!print_export_directory(database, exe_base)) { clean_exit(loadFile); }
		if (!print_export_functions(database, exe_base)) { clean_exit(loadFile); }
		if (!print_delayed_import_descriptors(database, exe_base)) { clean_exit(loadFile); }
		if (!print_base_relocations(database, exe_base)) { clean_exit(loadFile); }
		};

	//Build DOS -> Sections
	std::thread dos_thread(dos_lambda, database, exe_base, loadFile);
	std::thread nt_thread(nt_lambda, database, exe_base, loadFile);
	std::thread section_thread(section_lambda, database, exe_base, loadFile);
	dos_thread.join();
	nt_thread.join();
	section_thread.join();

	//Build DataDirectories
	std::thread import_thread(import_lambda, database, exe_base, loadFile);
	std::thread export_thread(export_lambda, database, exe_base, loadFile);
	std::thread delayed_import_thread(delayed_import_lambda, database, exe_base, loadFile);
	std::thread base_relocations_thread(base_relocations_lambda, database, exe_base, loadFile);
	import_thread.join();
	export_thread.join();
	delayed_import_thread.join();
	base_relocations_thread.join();

	//Print Database
	std::thread print_thread(print_lambda, database, exe_base, loadFile);
	print_thread.join();

    return true;
}

#elif _WIN64

bool start_pe_parser(PE_DATABASE* database, void* exe_base, HANDLE loadFile)
{

	auto dos_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) {
		if (!create_dos_header(database, exe_base)) { clean_exit(loadFile); } 
		};

	auto nt_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) {
		if (!create_nt_headers(database, exe_base)) { clean_exit(loadFile); } 
		};

	auto section_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) {
		if (!create_section_headers(database, exe_base)) { clean_exit(loadFile); } 
		};

	auto import_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) {
		if (!create_import_descriptors(database, exe_base)) { clean_exit(loadFile); } 
		};

	auto export_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) {
		if (!create_export_directory(database, exe_base)) { clean_exit(loadFile); } 
		};

	auto delayed_import_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) {
		if (!create_delayed_import_descriptors(database, exe_base)) { clean_exit(loadFile); } 
		};

	auto base_relocations_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) { 
		if (!create_page_relocations(database, exe_base)) { clean_exit(loadFile); } 
		};

	auto print_lambda = [](PE_DATABASE* database, void* exe_base, HANDLE loadFile) {
		if (!find_packer_type_simple(database)) { clean_exit(loadFile); }
		};


	//Build DOS -> Sections
	std::thread dos_thread(dos_lambda, database, exe_base, loadFile);
	std::thread nt_thread(nt_lambda, database, exe_base, loadFile);
	std::thread section_thread(section_lambda, database, exe_base, loadFile);
	dos_thread.join();
	nt_thread.join();
	section_thread.join();

	//Build DataDirectories
	/*std::thread import_thread(import_lambda, database, exe_base, loadFile);
	std::thread export_thread(export_lambda, database, exe_base, loadFile);
	std::thread delayed_import_thread(delayed_import_lambda, database, exe_base, loadFile);
	std::thread base_relocations_thread(base_relocations_lambda, database, exe_base, loadFile);
	import_thread.join();
	export_thread.join();
	delayed_import_thread.join();
	base_relocations_thread.join();*/

	//Print Database
	std::thread print_thread(print_lambda, database, exe_base, loadFile);
	print_thread.join();

	return true;
}

#endif