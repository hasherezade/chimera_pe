#pragma once
#include <Windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"

bool is_supported(LPSTR lib_name);

bool write_handle(LPCSTR lib_name, ULONGLONG call_via, LPSTR func_name, LPVOID modulePtr, bool is64);

bool solve_imported_funcs_b32(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr);
bool solve_imported_funcs_b64(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr);

//fills handles of the mapped pe file
bool apply_imports(PVOID modulePtr);