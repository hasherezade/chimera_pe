#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_raw_to_virtual.h"
#include "relocate.h"
#include "load_imports.h"

/*
run_injected_in_new_thread:
    hProcess - handle of the process where we injected the payload
    remote_code_ep - entry point of the injected code
*/
bool run_injected_in_new_thread(HANDLE hProcess, LPVOID remote_code_ep);

/*
inject_PE:
    hProcess - handle of the process where we want to inject
    payload - buffer with raw image of PE that we want to inject
    payload_size - size of the above
*/
bool inject_PE(HANDLE hProcess, BYTE* payload, SIZE_T payload_size);
