#pragma once
#include <Windows.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <iostream>

#include "sysutil.h"


bool get_process_name(IN HANDLE hProcess, OUT LPWSTR nameBuf, IN SIZE_T nameMax);

bool is_searched_process(DWORD processID, LPWSTR searchedName, bool is64b);

//find running process using Process32First/Process32Next
HANDLE find_running_process(LPWSTR searchedName);

//find running proccess using EnumProcesses
HANDLE find_running_process2(LPWSTR searchedName);

//create new process
HANDLE create_new_process1(IN LPWSTR path, OUT PROCESS_INFORMATION &pi, BOOL run_original);
