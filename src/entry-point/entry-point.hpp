#pragma once

#include <Windows.h>
#include <Shlwapi.h>
#include <Tlhelp32.h>
#include <iostream>
#include <thread>

typedef NTSTATUS(NTAPI* NtQueryInformationThreadType)(HANDLE ThreadHandle, unsigned int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

uint64_t pattern_scan(uint64_t start, size_t range, BYTE pattern[], const char* mask)
{
    auto pattern_length = (uint32_t)strlen(mask);

    for (auto i = 0; i < range - pattern_length; ++i)
    {
        bool found = true;
        for (auto j = 0; j < pattern_length; ++j)
        {
            if (mask[j] != '?' && (reinterpret_cast<BYTE*>(start))[i + j] != pattern[j])
            {
                found = false;
                break;
            }
        }

        return found ? start + i : 0;
    }
}