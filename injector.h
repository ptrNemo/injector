#pragma once

#include <string_view>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>

namespace injector {
    bool inject(const std::string_view& processName, const std::filesystem::path dllPath);
    bool eject(const std::string_view& processName, const std::string& dllName);
    bool callDllFunction(const std::string_view& processName, const std::string& dllName, const std::string& functionName);
    DWORD getPID(const std::string_view& processName);
    HMODULE getRMH(DWORD pid, const std::string& moduleBaseName);
}

