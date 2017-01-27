#include "load_imports.h"

// warning: it is recommended to solve only kernel32.dll and ntdll.dll by this way
// - because they are loaded by every process (and at the same base)
// rest of the imports should be filled by the payload (see: chimera_pe_payload_template)
#define SUPPORTED_LIB_NAME "kernel32.dll"
#define SUPPORTED_LIB_NAME2 "ntdll.dll"

// user32.dll is loaded by most of the processes (but not all)
// if your payload needs it, and the target doesn't have it, the application will crash!
#define SUPPORTED_LIB_NAME3 "user32.dll"
// if you want to include it add: 
// #define TARGET_HAS_USER32

bool is_name(LPSTR lib_name, LPSTR supported_lib)
{
    SIZE_T kernel_name_len = strlen(supported_lib);

    size_t lib_name_len = strlen(lib_name);

    for (size_t i = 0; i < kernel_name_len && i < lib_name_len; i++) {
        CHAR c = tolower(lib_name[i]);
        if (c != supported_lib[i]) return false;
    }
    return true;
}

bool is_supported(LPSTR lib_name)
{
    if (is_name(lib_name, SUPPORTED_LIB_NAME)) {
        return true;
    }
    if (is_name(lib_name, SUPPORTED_LIB_NAME2)) {
        return true;
    }
#ifdef TARGET_HAS_USER32
    if (is_name(lib_name, SUPPORTED_LIB_NAME3)) {
        return true;
    }
#endif
    return false;
}

bool write_handle(LPCSTR lib_name, ULONGLONG call_via, LPSTR func_name, LPVOID modulePtr, bool is64)
{
    size_t field_size = (is64) ? sizeof(ULONGLONG) : sizeof(DWORD);
    HMODULE hBase = LoadLibraryA(lib_name);
    if (hBase == NULL) return false;

    FARPROC hProc = GetProcAddress(hBase, func_name);
    LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
    memcpy(call_via_ptr, &hProc, field_size);
    printf("proc addr: %p -> %p\n", hProc, call_via_ptr);
    return true;
}

bool solve_imported_funcs_b32(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr)
{
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        DWORD *thunk_val = (DWORD*)thunk_ptr;
        DWORD *call_via_val = (DWORD*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return true;
        }
        //those two values are supposed to be the same before the file have imports filled
        //so, if they are different it means the handle is already filled
        if (*thunk_val == *call_via_val) {
            IMAGE_THUNK_DATA32* desc = (IMAGE_THUNK_DATA32*) thunk_ptr;
            if (desc->u1.Function == NULL) break;

            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);
            if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                printf("Imports by ordinals are not supported!\n");
                return false;
            }
            LPSTR func_name = by_name->Name;
            printf("name: %s\n", func_name);
            if (!write_handle(lib_name, call_via, func_name, modulePtr, false)) {
                printf("Could not load the handle!\n");
                return false;
            }
        }
        call_via += sizeof(DWORD);
        thunk_addr += sizeof(DWORD);
    } while (true);
    return true;
}

bool solve_imported_funcs_b64(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr)
{
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        ULONGLONG *thunk_val = (ULONGLONG*)thunk_ptr;
        ULONGLONG *call_via_val = (ULONGLONG*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return true;
        }
        //those two values are supposed to be the same before the file have imports filled
        //so, if they are different it means the handle is already filled
        if (*thunk_val == *call_via_val) {
            IMAGE_THUNK_DATA64* desc = (IMAGE_THUNK_DATA64*)thunk_ptr;
            if (desc->u1.Function == NULL) break;

            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
            if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                printf("Imports by ordinals are not supported!\n");
                return false;
            }
            LPSTR func_name = by_name->Name;
            printf("name: %s\n", func_name);
            if (!write_handle(lib_name, call_via, func_name, modulePtr, true)) {
                printf("Could not load the handle!\n");
                return false;
            }
        }
        call_via += sizeof(ULONGLONG);
        thunk_addr += sizeof(ULONGLONG);
    } while (true);
    return true;
}

//fills handles of mapped pe file
bool apply_imports(PVOID modulePtr)
{
    bool is64 = is64bit((BYTE*)modulePtr);

    IMAGE_DATA_DIRECTORY *importsDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    DWORD maxSize = importsDir->Size;
    DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    bool isAllFilled = true;
    DWORD parsedSize = 0;

    printf("---IMP---\n");
    while (parsedSize < maxSize) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }

        printf("Imported Lib: %x : %x : %x\n", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        printf("name: %s\n", lib_name);
        if (!is_supported(lib_name)) {
            isAllFilled = false;
            //skip libraries that cannot be filled
            continue;
        }

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;
        if (is64) {
            printf("64 bit import\n");
            solve_imported_funcs_b64(lib_name, call_via, thunk_addr, modulePtr);
        }
        else {
            printf("32 bit import\n");
            solve_imported_funcs_b32(lib_name, call_via, thunk_addr, modulePtr);
        }
        
    }
    if (isAllFilled == false) {
        printf("WARNING: Some libraries are not filled!\nFor this method to work, EXE cannot have other imports than kernel32.dll or user32.dll!\n");
    }
    printf("---------\n");
    return isAllFilled;
}
