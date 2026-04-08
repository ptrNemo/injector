#include "injector.h"

/**
 * Inject into process the specified dll creating a thread
 *
 * @param processName Target process name
 * @param dllPath Dll absolute path
 * @return True if successful injection, false if fails
 */
bool injector::inject(const std::string_view& processName, const std::filesystem::path dllPath) {
    if (std::filesystem::exists(dllPath))
        return false;

    DWORD pid = getPID(processName);
    if (pid == 0) return false;

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProc) return false;

    void* remoteBuf = VirtualAllocEx(
        hProc,
        nullptr,
        MAX_PATH,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteBuf) {
        CloseHandle(hProc);
        return false;
    }

    WriteProcessMemory(
        hProc,
        remoteBuf,
        dllPath.c_str(),
        strlen(reinterpret_cast<const char *>(dllPath.c_str())) + 1,
        nullptr
    );

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

        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return true;
}

/**
 * Ejects from target the dll
 *
 * @param processName Target process name
 * @param dllName Dll name
 * @return True if successful ejection, false if fails
 */
bool injector::eject(const std::string_view& processName, const std::string& dllName) {
    DWORD pid = getPID(processName);
    if (pid == 0) return false;

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProc) return false;

    HMODULE hModule = getRMH(pid, dllName);
    if (!hModule) {
        CloseHandle(hProc);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    if (!hKernel32) {
        CloseHandle(hProc);
        return false;
    }

    auto freeLibraryThread = reinterpret_cast<PTHREAD_START_ROUTINE>(GetProcAddress(hKernel32, "FreeLibrary"));
    if (!freeLibraryThread) {
        CloseHandle(hProc);
        return false;
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
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);

    if (getRMH(pid, dllName)) //check if module has been removed
        return false;

    CloseHandle(hProc);

    return true;
}

/**
 * Calling exported function from process
 *
 * @param processName Target process name
 * @param dllName Loaded dll module name
 * @param functionName Function name
 * @return True if successful call, false if fails
 */
bool injector::callDllFunction(const std::string_view& processName, const std::string& dllName, const std::string& functionName) {
    /* TODO
     * get process id
     * open process
     * get local module handle for the same dll
     * get exported function address locally
     * compute function offset from local module base
     * get remote module handle for the dll in target process
     * compute remote function address
     * create remote thread to call the remote function
     * wait for thread completion
     * check exit code
     * close handles
    */
    DWORD pid = getPID(processName);
    if (pid == 0) return false;

    HMODULE hLocalDll = LoadLibraryA(dllName.c_str());
    if (!hLocalDll)
        return false;

    FARPROC localFnAddress = GetProcAddress(hLocalDll, functionName.c_str());
    if (!localFnAddress) {
        FreeLibrary(hLocalDll);
        return false;
    }

    std::ptrdiff_t fnOffset = reinterpret_cast<std::uintptr_t>(localFnAddress) - reinterpret_cast<std::uintptr_t>(hLocalDll);
    if (!fnOffset) {
        FreeLibrary(hLocalDll);
        return false;
    }

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
        return false;
    }

    HMODULE hRemoteModule = getRMH(pid, dllName);
    if (!hRemoteModule) {
        FreeLibrary(hLocalDll);
        CloseHandle(hProc);
        return false;
    }

    auto pRemoteFnThread = reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<std::uintptr_t>(hRemoteModule) + fnOffset);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pRemoteFnThread, nullptr, 0, nullptr);
    if (!hThread) {
        FreeLibrary(hLocalDll);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    FreeLibrary(hLocalDll);
    CloseHandle(hProc);

    return true;
}

/**
 * For a given processName returns the pid
 *
 * @param processName Target process name
 * @return Process pid if process found or 0 if fails
 */
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

/**
 * For a given process and a given module name, returns the handle to that module
 *
 * @param pid Process target id
 * @param moduleBaseName Loaded dll name
 * @return Handle to the found module
 */
HMODULE injector::getRMH(DWORD pid, const std::string& moduleBaseName) {
    HMODULE hModule = nullptr;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, reinterpret_cast<const wchar_t *>(moduleBaseName.c_str())) == 0) {
                hModule = me.hModule;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return hModule;
}