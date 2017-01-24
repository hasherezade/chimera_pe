#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"
#include "sysutil.h"

// Map raw PE into virtual memory of remote process
bool copy_pe_to_virtual_r(BYTE* payload, SIZE_T payload_size, LPVOID baseAddress, HANDLE hProcess)
{
    if (payload == NULL) return false;

    IMAGE_NT_HEADERS32* payload_nt_hdr = get_nt_hrds32(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    SIZE_T written = 0;

    //copy payload's headers:
    const DWORD kHdrsSize = payload_nt_hdr->OptionalHeader.SizeOfHeaders;
    if (!WriteProcessMemory(hProcess, baseAddress, payload, kHdrsSize, &written)) {
        return false;
    }
    if (written != kHdrsSize) return false;

    printf("Copied payload's headers to: %p\n", baseAddress);

    LPVOID secptr = &(payload_nt_hdr->OptionalHeader);
    const DWORD kOptHdrSize = payload_nt_hdr->FileHeader.SizeOfOptionalHeader;

    //copy all the sections, one by one:
    secptr = LPVOID((ULONGLONG) secptr + kOptHdrSize);

    printf("Coping sections remotely:\n");
    for (WORD i = 0; i < payload_nt_hdr->FileHeader.NumberOfSections; i++) {
       PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));

       LPVOID section_place = (BYTE*) baseAddress + next_sec->VirtualAddress;
       LPVOID section_raw_ptr = payload + next_sec->PointerToRawData;

       if (!WriteProcessMemory(hProcess, section_place, section_raw_ptr, next_sec->SizeOfRawData, &written)) {
           return false;
       }
       if (written != next_sec->SizeOfRawData) return false;
       printf("[+] %s to: %p\n", next_sec->Name, section_place);
    }
    return true;
}

// Map raw PE into virtual memory of local process:
bool copy_pe_to_virtual_l(BYTE* payload, SIZE_T payload_size, LPVOID baseAddress)
{
    if (payload == NULL) return false;

    IMAGE_NT_HEADERS32* payload_nt_hdr = get_nt_hrds32(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }
    //copy payload's headers:
    const DWORD kHdrsSize = payload_nt_hdr->OptionalHeader.SizeOfHeaders;
    memcpy(baseAddress, payload, kHdrsSize);

    LPVOID secptr = &(payload_nt_hdr->OptionalHeader);
    const DWORD kOptHdrSize = payload_nt_hdr->FileHeader.SizeOfOptionalHeader;

    //copy all the sections, one by one:
    secptr = LPVOID((ULONGLONG) secptr + kOptHdrSize);

    printf("Coping sections locally:\n");
    for (WORD i = 0; i < payload_nt_hdr->FileHeader.NumberOfSections; i++) {
       PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));

       LPVOID section_place = (BYTE*) baseAddress + next_sec->VirtualAddress;
       LPVOID section_raw_ptr = payload + next_sec->PointerToRawData;
       memcpy(section_place, section_raw_ptr, next_sec->SizeOfRawData);
       printf("[+] %s to: %p\n", next_sec->Name, section_place);
    }
    return true;
}

bool sections_raw_to_virtual(BYTE* payload, SIZE_T destBufferSize, OUT BYTE* destAddress)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    IMAGE_FILE_HEADER *fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    if (!validate_ptr(payload, destBufferSize, payload, hdrsSize)) {
        return false;
    }
    //copy payload's headers:
    memcpy(destAddress, payload, hdrsSize);

    //copy all the sections, one by one:
    printf("Coping sections:\n");

    SIZE_T raw_end = 0;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr(payload, destBufferSize, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
            return false;
        }
        LPVOID section_mapped = destAddress + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = (BYTE*)payload +  next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;
        raw_end = next_sec->SizeOfRawData + next_sec->PointerToRawData;
        
        if (next_sec->VirtualAddress + sec_size >= destBufferSize) {
            printf("[!] Virtual section size is out ouf bounds: %lx\n", sec_size);
            sec_size = SIZE_T(destBufferSize - next_sec->VirtualAddress);
            printf("[!] Truncated to maximal size: %lx\n", sec_size);
        }
        if (next_sec->VirtualAddress >= destBufferSize && sec_size != 0) {
            printf("[-] VirtualAddress of section is out ouf bounds: %lx\n", static_cast<SIZE_T>(next_sec->VirtualAddress));
            return false;
        }
        if (next_sec->PointerToRawData + sec_size >= destBufferSize) {
            printf("[-] Raw section size is out ouf bounds: %lx\n", sec_size);
            return false;
        }
        printf("[+] %s to: %p\n", next_sec->Name, section_raw_ptr);
        memcpy(section_mapped, section_raw_ptr, sec_size);
    }
    return true;
}