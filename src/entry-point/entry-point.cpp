#include "entry-point.hpp"

void main_thread(HMODULE dll_module)
{
    BYTE pattern[] = { 0x0F, 0x85, 0x83, 0x00, 0x00, 0x00, 0x48, 0x21, 0x5C };
    const char* mask = "xxxxxxxxx";

    const auto lib = LoadLibraryA("ntdll.dll");
    if (!lib)
    {
        return;
    }

    const auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadType>(GetProcAddress(lib, "NtQueryInformationThread"));
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 thread_entry = { sizeof(THREADENTRY32) };

    const auto module_base = reinterpret_cast<uint64_t>(GetModuleHandleA(nullptr));
    const auto CImmersiveWatermark = pattern_scan(module_base, 0x200000, pattern, mask);
    if (!CImmersiveWatermark)
    {
        return;
    }

    DWORD vp_old_protection{};
    VirtualProtect((void*)CImmersiveWatermark, 6, PAGE_EXECUTE_READWRITE, &vp_old_protection);

    *reinterpret_cast<char*>(CImmersiveWatermark) = 0xE9; // jmp
    *reinterpret_cast<char*>(CImmersiveWatermark + 0x1) = 0x84; // offset
    memset((char*)CImmersiveWatermark + 0x2, 0x00, 2); // ...
    *reinterpret_cast<char*>(CImmersiveWatermark + 0x5) = 0x90; // nop

    VirtualProtect((void*)CImmersiveWatermark, 6, vp_old_protection, &vp_old_protection);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    for (auto has_next = Thread32First(snapshot, &thread_entry); has_next; has_next = Thread32Next(snapshot, &thread_entry))
    {
        if (thread_entry.th32OwnerProcessID == GetCurrentProcessId())
        {
            const auto thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread_entry.th32ThreadID);
            uint64_t entry_point = 0;

            if (NtQueryInformationThread(thread, 0x09, &entry_point, sizeof(entry_point), nullptr) == 0)
            {
                if (entry_point != 0 && *reinterpret_cast<char*>(entry_point + 0x16) == 0x41)
                {
                    CloseHandle(snapshot);
                    TerminateThread(thread, 0);
                }
            }

            if (thread)
            {
                CloseHandle(thread);
            }
        }
    }

    CloseHandle(snapshot);
    FreeLibrary(dll_module);
}

bool __stdcall DllMain(HMODULE dll_module, uint64_t reason_for_call, void*)
{
    if (reason_for_call == DLL_PROCESS_ATTACH)
    {
        std::thread(main_thread, dll_module).detach();
    }
    return true;
}