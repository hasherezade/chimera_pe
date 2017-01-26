#pragma once
#include "sysutil.h"

#include <windows.h>
#include <stdio.h>

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

bool is_compiled_32b()
{
#if defined(_WIN64)
    return false;
#endif
    return true;
}

bool is_wow64(HANDLE process = NULL)
{
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    BOOL bIsWow64 = false;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    if (fnIsWow64Process == NULL) {
        return false;
    }
    if (process == NULL) {
        process = GetCurrentProcess();
    }
    if (!fnIsWow64Process(process, &bIsWow64)) {
        return false;
	}
    if (bIsWow64 == TRUE) {
        return  true; //64 bit
    }
	return false; //32 bit
}

bool is_system32b()
{
    //is the current application 32 bit?
    if (!is_compiled_32b()) {
        return false;
    }
	//check if it is running under WoW
    return !is_wow64();
}

bool is_process_64b(HANDLE hProcess)
{
    if (is_system32b()) {
        return false;
    }
    if (hProcess == NULL) {
        hProcess = GetCurrentProcess();
    }
    return !is_wow64(hProcess);
}

bool validate_ptr(LPVOID buffer_bgn, SIZE_T buffer_size, LPVOID field_bgn, SIZE_T field_size)
{
    ULONGLONG start = (ULONGLONG)buffer_bgn;
    ULONGLONG end = start + buffer_size;

    ULONGLONG field_end = (ULONGLONG)field_bgn + field_size;

    if ((ULONGLONG)field_bgn < start) {
        return false;
    }
    if (field_end >= end) {
        return false;
    }
    return true;
}
