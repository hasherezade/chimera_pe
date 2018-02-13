#include <Windows.h>

#include "reflective/reflective_imports_load.h"

#include "start_actions.h"

int main(int argc, char **argv)
{
    if (!apply_imports()) {
        return -2;
    }
    return start_actions(argc, argv);
}
