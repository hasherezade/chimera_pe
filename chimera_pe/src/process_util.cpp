#include "process_util.h"

bool get_process_name(IN HANDLE hProcess, OUT LPWSTR nameBuf, IN SIZE_T nameMax)
{
    memset(nameBuf, 0, nameMax);
    DWORD out = GetModuleBaseName(hProcess, 0, nameBuf, nameMax);
    if (out == 0) {
        out = GetProcessImageFileName(hProcess, nameBuf, nameMax);
    }
    return (out > 0);
}

inline WCHAR to_lowercase(WCHAR c1)
{
    if (c1 <= L'Z' && c1 >= L'A') {
        c1 = (c1 - L'A') + L'a';
    }
    return c1;
}

bool is_wanted_module(LPWSTR curr_name, LPWSTR wanted_name)
{
    if (wanted_name == NULL || curr_name == NULL) return false;

    WCHAR *curr_end_ptr = curr_name;
    while (*curr_end_ptr != L'\0') {
        curr_end_ptr++;
    }
    if (curr_end_ptr == curr_name) return false;

    WCHAR *wanted_end_ptr = wanted_name;
    while (*wanted_end_ptr != L'\0') {
        wanted_end_ptr++;
    }
    if (wanted_end_ptr == wanted_name) return false;

    while ((curr_end_ptr != curr_name) && (wanted_end_ptr != wanted_name)) {

        if (to_lowercase(*wanted_end_ptr) != to_lowercase(*curr_end_ptr)) {
            return false;
        }
        wanted_end_ptr--;
        curr_end_ptr--;
    }
    return true;
}

bool is_searched_process(DWORD processID, LPWSTR searchedName, bool is64b)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) return false;
    bool proc64b = !is_system32b() && !is_wow64(hProcess);
    if (is64b != proc64b) {
        CloseHandle(hProcess);
        return false;
    }
    WCHAR szProcessName[MAX_PATH];
    if (get_process_name(hProcess, szProcessName, MAX_PATH)) {
        if (is_wanted_module(szProcessName, searchedName) != NULL) {
            CloseHandle(hProcess);
            printf("%S  (PID: %u) : %d\n", szProcessName, processID, proc64b);
            return true;
        }
    }
    CloseHandle(hProcess);
    return false;
}

HANDLE find_running_process(LPWSTR searchedName)
{
    bool is64b = !is_compiled_32b();

    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    PROCESSENTRY32 process_entry = { 0 };
    process_entry.dwSize = sizeof(process_entry);

    if (!Process32First(hProcessSnapShot, &process_entry)) {
        return NULL;
    }

    do
    {
        if (is_searched_process(process_entry.th32ProcessID, searchedName, is64b)) {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_entry.th32ProcessID);
            return hProcess;
        }

    } while (Process32Next(hProcessSnapShot, &process_entry));

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return NULL;
}


HANDLE find_running_process2(LPWSTR searchedName)
{
    bool is64b = !is_compiled_32b();
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return NULL;
    }

    //calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    //search handle to the process of defined name
    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            if (is_searched_process(aProcesses[i], searchedName, is64b)) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
                return hProcess;
            }
        }
    }
    return NULL;
}

HANDLE create_new_process1(IN LPWSTR path, OUT PROCESS_INFORMATION &pi, BOOL run_original)
{
    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    DWORD flags = DETACHED_PROCESS;
    if (run_original == FALSE) {
        flags |= CREATE_SUSPENDED;
    }

    if (!CreateProcessW(
            NULL,
            path,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            FALSE, //bInheritHandles
            flags, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return NULL;
    }

    return pi.hProcess;
}
