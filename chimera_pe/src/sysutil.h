#pragma once

#include <Windows.h>

bool is_compiled_32b();
bool is_wow64(HANDLE process);
bool is_system32b();
bool is_process_64b(HANDLE hProcess = NULL);

bool validate_ptr(LPVOID buffer_bgn, SIZE_T buffer_size, LPVOID field_bgn, SIZE_T field_size);