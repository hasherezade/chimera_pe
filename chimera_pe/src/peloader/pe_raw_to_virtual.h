#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"
#include "../sysutil.h"

// Map raw PE into virtual memory of local process:
bool sections_raw_to_virtual(BYTE* payload, SIZE_T destBufferSize, BYTE* destAddress);

// set a new image base in headers
bool update_image_base(BYTE* payload, PVOID destImageBase);

// get pointer to sections header:
LPVOID get_sec_ptr(BYTE* payload);

// get number of sections:
WORD get_sec_number(BYTE* payload);

//get size of headers
DWORD get_hdrs_size(BYTE* payload);