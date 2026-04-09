#pragma once

#include <string_view>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>

#define ERROR_DLL_FOUND 1169

namespace injector {
    enum class InjectError {
        None,
        InvalidArgument,
        ProcessNotFound,
        OpenProcessFailed,
        MemoryAllocationFailed,
        ThreadCreationFailed,
        ModuleNotLoaded,
        ModuleNotEjected,
        FunctionNotFound,
        MemoryWriteFailed
    };

    struct InjectStatus {
        bool success;
        InjectError error;
        DWORD nativeError;
    };

    /**
    * Inject into process the specified dll creating a thread
    *
    * @param processName Target process name
    * @param dllPath Dll absolute path
    * @return True if successful injection, false if fails
    */
    InjectStatus inject(const std::string_view& processName, const std::filesystem::path dllPath);

    /**
    * Ejects from target the dll
    *
    * @param processName Target process name
    * @param dllName Dll name
    * @return True if successful ejection, false if fails
    */
    InjectStatus eject(const std::string_view& processName, const std::string& dllName);

    /**
    * Calling exported function from process
    *
    * @param processName Target process name
    * @param dllName Loaded dll module name
    * @param functionName Function name
    * @return True if successful call, false if fails
    */
    InjectStatus callDllFunction(const std::string_view& processName, const std::string& dllName, const std::string& functionName);

    /**
    * For a given processName returns the pid
    *
    * @param processName Target process name
    * @return Process pid if process found or 0 if fails
    */
    DWORD getPID(const std::string_view& processName);

    /**
    * For a given process and a given module name, returns the handle to that module
    *
    * @param pid Process target id
    * @param moduleBaseName Loaded dll name
    * @return Handle to the found module
    */
    HMODULE getRMH(DWORD pid, const std::string& moduleBaseName);
}

