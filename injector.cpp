#include "injector.h"

injector::InjectStatus injector::inject(const std::string_view& processName, const std::filesystem::path dllPath) {
    if (!std::filesystem::exists(dllPath))
        return {false, InjectError::InvalidArgument, ERROR_FILE_NOT_FOUND};

    DWORD pid = getPID(processName);
    if (pid == 0) return {false, InjectError::ProcessNotFound, ERROR_PROC_NOT_FOUND};

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProc) return {false, InjectError::OpenProcessFailed, GetLastError()};

    void* remoteBuf = VirtualAllocEx(
        hProc,
        nullptr,
        MAX_PATH,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteBuf) {
        CloseHandle(hProc);
        return {false, InjectError::MemoryAllocationFailed, GetLastError()};
    }

    if (!WriteProcessMemory(
        hProc,
        remoteBuf,
        dllPath.string().c_str(),
        dllPath.string().size() + 1,
        nullptr
    )) {
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return {false, InjectError::MemoryWriteFailed, GetLastError()};
    }

    HANDLE hThread = CreateRemoteThread(
        hProc,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
        remoteBuf,
        0,
        nullptr
    );

    if (!hThread) {
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);

        return {false, InjectError::ThreadCreationFailed, GetLastError()};
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return {true, InjectError::None, ERROR_SUCCESS};
}

injector::InjectStatus injector::eject(const std::string_view& processName, const std::string& dllName) {
    DWORD pid = getPID(processName);
    if (pid == 0) return {false, InjectError::ProcessNotFound, ERROR_PROC_NOT_FOUND};

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProc) return {false, InjectError::OpenProcessFailed, GetLastError()};

    HMODULE hModule = getRMH(pid, dllName);
    if (!hModule) {
        CloseHandle(hProc);
        return {false, InjectError::ModuleNotLoaded, ERROR_DLL_NOT_FOUND};
    }

    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    if (!hKernel32) {
        CloseHandle(hProc);
        return {false, InjectError::ModuleNotLoaded, GetLastError()};
    }

    auto freeLibraryThread = reinterpret_cast<PTHREAD_START_ROUTINE>(GetProcAddress(hKernel32, "FreeLibrary"));
    if (!freeLibraryThread) {
        CloseHandle(hProc);
        return {false, InjectError::FunctionNotFound, GetLastError()};
    }

    HANDLE hThread = CreateRemoteThread(
        hProc,
        nullptr,
        0,
        freeLibraryThread,
        hModule,
        0,
        nullptr);

    if (!hThread) {
        CloseHandle(hProc);
        return {false, InjectError::ThreadCreationFailed, GetLastError()};
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);

    if (getRMH(pid, dllName)) //check if module has been removed
        return {false, InjectError::ModuleNotEjected, ERROR_DLL_FOUND};

    CloseHandle(hProc);

    return {true, InjectError::None, ERROR_SUCCESS};
}

injector::InjectStatus injector::callDllFunction(const std::string_view& processName, const std::string& dllName, const std::string& functionName) {
    DWORD pid = getPID(processName);
    if (pid == 0) return {false, InjectError::ProcessNotFound, ERROR_PROC_NOT_FOUND};

    HMODULE hLocalDll = LoadLibraryA(dllName.c_str());
    if (!hLocalDll)
        return {false, InjectError::ModuleNotLoaded, GetLastError()};

    FARPROC localFnAddress = GetProcAddress(hLocalDll, functionName.c_str());
    if (!localFnAddress) {
        FreeLibrary(hLocalDll);
        return {false, InjectError::FunctionNotFound, GetLastError()};
    }

    std::ptrdiff_t fnOffset = reinterpret_cast<std::uintptr_t>(localFnAddress) - reinterpret_cast<std::uintptr_t>(hLocalDll);

    HANDLE hProc = OpenProcess(
    PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (!hProc) {
        FreeLibrary(hLocalDll);
        return {false, InjectError::OpenProcessFailed, GetLastError()};
    }

    HMODULE hRemoteModule = getRMH(pid, dllName);
    if (!hRemoteModule) {
        FreeLibrary(hLocalDll);
        CloseHandle(hProc);
        return {false, InjectError::ModuleNotLoaded, ERROR_DLL_NOT_FOUND};
    }

    auto pRemoteFnThread = reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<std::uintptr_t>(hRemoteModule) + fnOffset);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pRemoteFnThread, nullptr, 0, nullptr);
    if (!hThread) {
        FreeLibrary(hLocalDll);
        CloseHandle(hProc);
        return {false, InjectError::ThreadCreationFailed, GetLastError()};
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    FreeLibrary(hLocalDll);
    CloseHandle(hProc);

    return {true, InjectError::None, ERROR_SUCCESS};
}

DWORD injector::getPID(const std::string_view& processName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            if (!_stricmp(pe.szExeFile, processName.data())) {
                procId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return procId;
}

HMODULE injector::getRMH(DWORD pid, const std::string& moduleBaseName) {
    HMODULE hModule = nullptr;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            if (!_stricmp(me.szModule, moduleBaseName.c_str())) {
                hModule = me.hModule;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return hModule;
}