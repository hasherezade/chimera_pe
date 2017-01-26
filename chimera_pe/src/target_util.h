#pragma once
#include <Windows.h>
#include <stdio.h>

//set of some sample injection targets:
namespace target {
    //get the path of default browser
    bool get_default_browser(LPWSTR lpwOutPath, DWORD szOutPath);

    //get the path of system calc
    bool get_calc_path(LPWSTR lpwOutPath, DWORD szOutPath);

    //get the path of svchost
    bool get_svchost_path(LPWSTR lpwOutPath, DWORD szOutPath);

    //get the path of explorer exe
    bool get_explorer_path(LPWSTR lpwOutPath, DWORD szOutPath);
};