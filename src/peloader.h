#pragma once

#include <cstdint>
#include <string>
#include <Winsock2.h>
#include <Windows.h>

class PELoader
{
private:
    void(*entryPoint)();

    uint8_t *_data = nullptr;
    uint8_t *_imageBase = nullptr;

    uintptr_t _entry = 0;

    PIMAGE_DOS_HEADER _dosHeader = nullptr;
    PIMAGE_NT_HEADERS _originalNTHeader = nullptr;
    PIMAGE_NT_HEADERS _newNTHeader = nullptr;

    PIMAGE_DATA_DIRECTORY GetHeaderDictionary(uint32_t idx)
    {
        return &_newNTHeader->OptionalHeader.DataDirectory[idx];
    }

    HMODULE(*_libraryLoader)(const char*) = nullptr;
    FARPROC(*_procResolver)(HMODULE, const char*) = nullptr;

public:
    PELoader() = default;
    virtual ~PELoader();

    void SetLibraryLoader(HMODULE(*loader)(const char*))
    {
        _libraryLoader = loader;
    }

    void SetProcResolver(FARPROC(*func)(HMODULE, const char*))
    {
        _procResolver = func;
    }

    void VerifyPE();
    void LoadHeaders();
    void LoadSections();
    void Relocate();
    void BuildIAT();
    void ApplyPermissions();
    void DoTLS();

    uint8_t* GetImageBase() { return _imageBase; }

    int32_t LoadFile(const std::string &);

    inline void Run()
    {
        this->entryPoint();
    }
};