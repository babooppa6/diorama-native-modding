#include "peloader.h"
#include <stdexcept>
#include <algorithm>

#include <Winternl.h>

PELoader::~PELoader()
{
    delete[] _data;
}

int32_t PELoader::LoadFile(const std::string &fileName)
{
    FILE* file = nullptr;
    fopen_s(&file, fileName.c_str(), "rb");

    if (!file)
    {
        return -1;
    }

    uint32_t length = 0;

    fseek(file, 0, SEEK_END);
    length = ftell(file);

    _data = new uint8_t[length];

    fseek(file, 0, SEEK_SET);
    fread(_data, 1, length, file);

    fclose(file);

    try
    {
        VerifyPE();
    }
    catch (std::exception&)
    { }

    LoadHeaders();

    LoadSections();
    Relocate();
    BuildIAT();
    ApplyPermissions();
    DoTLS();

    ApplyPermissions();

    entryPoint = ((void(*)(void))(_newNTHeader->OptionalHeader.ImageBase + _newNTHeader->OptionalHeader.AddressOfEntryPoint));
    _entry = (uintptr_t)entryPoint;
    return 0;
}

void PELoader::VerifyPE()
{
    _dosHeader = (PIMAGE_DOS_HEADER)(_data);
    if (_dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        throw std::runtime_error("Invalid DOS Signature");
    }

    _originalNTHeader = (PIMAGE_NT_HEADERS)(&_data[_dosHeader->e_lfanew]);
    if (_originalNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        throw std::runtime_error("Invalid NT Signature");
    }

    if (_originalNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        throw std::runtime_error("You cannot load a x64 executable into a x32 executable");
    }
    else if (_originalNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        throw std::runtime_error("You can only load I386 executables");
    }
}

using POINTER_TYPE = DWORD;
void PELoader::LoadHeaders()
{
    _imageBase = static_cast<uint8_t*>(VirtualAlloc((LPVOID)(_originalNTHeader->OptionalHeader.ImageBase), _originalNTHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (_imageBase == NULL)
    {
        _imageBase = static_cast<uint8_t*>(VirtualAlloc(NULL, _originalNTHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (_imageBase == NULL)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            throw std::bad_alloc();
        }
    }

    uint8_t *headers = static_cast<uint8_t*>(VirtualAlloc(_imageBase, _originalNTHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE));
    memcpy(headers, _data, _originalNTHeader->OptionalHeader.SizeOfHeaders);

    _newNTHeader = (PIMAGE_NT_HEADERS)&((const uint8_t*)(headers))[_dosHeader->e_lfanew];
    _newNTHeader->OptionalHeader.ImageBase = (POINTER_TYPE)_imageBase;
}

void PELoader::BuildIAT()
{
    PIMAGE_DATA_DIRECTORY directory = GetHeaderDictionary(IMAGE_DIRECTORY_ENTRY_IMPORT);

    if (directory->Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(_newNTHeader->OptionalHeader.ImageBase + directory->VirtualAddress);
        for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++)
        {
            HMODULE handle = NULL;
            auto lib = (LPCSTR)(_newNTHeader->OptionalHeader.ImageBase + importDesc->Name);
            if (_libraryLoader)
            {
                handle = _libraryLoader(lib);
            }
            else
            {
                handle = LoadLibraryA(lib);
            }

            if (handle == NULL)
            {
                SetLastError(ERROR_MOD_NOT_FOUND);
                break;
            }

            POINTER_TYPE *thunkRef = (POINTER_TYPE *)(_newNTHeader->OptionalHeader.ImageBase + importDesc->OriginalFirstThunk);
            FARPROC *funcRef = (FARPROC *)(_newNTHeader->OptionalHeader.ImageBase + importDesc->FirstThunk);

            if (!importDesc->OriginalFirstThunk) // no hint table
            {
                thunkRef = (POINTER_TYPE *)(_newNTHeader->OptionalHeader.ImageBase + importDesc->FirstThunk);
            }

            for (; *thunkRef, *funcRef; thunkRef++, funcRef++)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
                {
                    *funcRef = GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
                }
                else
                {
                    auto proc = (LPCSTR)&((PIMAGE_IMPORT_BY_NAME)(_newNTHeader->OptionalHeader.ImageBase + (*thunkRef)))->Name;
                    if (_procResolver)
                    {
                        *funcRef = _procResolver(handle, proc);
                    }
                    else
                    {
                        *funcRef = GetProcAddress(handle, proc);
                    }
                }
            }
        }
    }
}

void PELoader::ApplyPermissions()
{
#define imageOffset 0

    auto section = IMAGE_FIRST_SECTION(_newNTHeader);
    for (int32_t i = 0; i < _newNTHeader->FileHeader.NumberOfSections; i++, section++)
    {
        bool executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool writeable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) // section is not needed any more and can safely be freed
        {
            VirtualFree((LPVOID)((POINTER_TYPE)section->Misc.PhysicalAddress | imageOffset), section->SizeOfRawData, MEM_DECOMMIT);
            continue;
        }

        DWORD protect = PAGE_NOACCESS;

        if (!executable)
        {
            if (!readable)
            {
                if (!writeable)
                {
                    protect = PAGE_NOACCESS;
                }
                else
                {
                    protect = PAGE_WRITECOPY;
                }
            }
            else
            {
                if (!writeable)
                {
                    protect = PAGE_READONLY;
                }
                else
                {
                    protect = PAGE_READWRITE;
                }
            }
        }
        else
        {
            if (!readable)
            {
                if (!writeable)
                {
                    protect = PAGE_EXECUTE;
                }
                else
                {
                    protect = PAGE_EXECUTE_WRITECOPY;
                }
            }
            else
            {
                if (!writeable)
                {
                    protect = PAGE_EXECUTE_READ;
                }
                else
                {
                    protect = PAGE_EXECUTE_READWRITE;
                }
            }
        }

        if (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
        {
            protect |= PAGE_NOCACHE;
        }

        DWORD size = section->SizeOfRawData;
        if (size == 0)
        {
            if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            {
                size = _newNTHeader->OptionalHeader.SizeOfInitializedData;
            }
            else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            {
                size = _newNTHeader->OptionalHeader.SizeOfUninitializedData;
            }
        }

        if (size > 0 && VirtualProtect((LPVOID)((POINTER_TYPE)section->Misc.PhysicalAddress | imageOffset), size, protect, &protect) == 0)
        {
#if DEBUG
            OutputDebugStringA("Failed to apply permission\n");
#endif
        }
    }
}

void PELoader::DoTLS()
{
    auto directory = GetHeaderDictionary(IMAGE_DIRECTORY_ENTRY_TLS);
    

    const IMAGE_TLS_DIRECTORY *sourceTls = (PIMAGE_TLS_DIRECTORY)(_newNTHeader->OptionalHeader.ImageBase + directory->VirtualAddress);

    // Copy TLS data
    {
        auto size = sourceTls->EndAddressOfRawData - sourceTls->StartAddressOfRawData;

        DWORD old;
        VirtualProtect((LPVOID *)__readfsdword(0x2C), size, PAGE_READWRITE, &old);

        memcpy(*(LPVOID *)__readfsdword(0x2C), reinterpret_cast<uintptr_t*>(sourceTls->StartAddressOfRawData), size);
    }

    if (directory->VirtualAddress > 0)
    {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(_newNTHeader->OptionalHeader.ImageBase + directory->VirtualAddress);
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
        if (callback)
        {
            while (*callback)
            {
                (*callback)((LPVOID)_newNTHeader->OptionalHeader.ImageBase, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
        }
    }
}

void PELoader::LoadSections()
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(_newNTHeader);

    for (int32_t i = 0; i < _newNTHeader->FileHeader.NumberOfSections; i++, section++)
    {
        if (section->SizeOfRawData == 0)
        {
            if (_newNTHeader->OptionalHeader.SectionAlignment > 0)
            {
                auto addr = (LPVOID)(_newNTHeader->OptionalHeader.ImageBase + section->VirtualAddress);
                uint8_t *dest = static_cast<uint8_t*>(VirtualAlloc(addr, _newNTHeader->OptionalHeader.SectionAlignment, MEM_COMMIT, PAGE_READWRITE));

                section->Misc.PhysicalAddress = (DWORD)(POINTER_TYPE)dest;
                memset(dest, 0, _newNTHeader->OptionalHeader.SectionAlignment);
            }
        }
        else
        {
            auto addr = (LPVOID)(_newNTHeader->OptionalHeader.ImageBase + section->VirtualAddress);
            uint8_t *dest = static_cast<uint8_t*>(VirtualAlloc(addr, section->SizeOfRawData, MEM_COMMIT, PAGE_EXECUTE_READWRITE));

            uint32_t sizeOfData = std::min(section->SizeOfRawData, section->Misc.VirtualSize);

            memcpy(dest, &_data[section->PointerToRawData], sizeOfData);
            section->Misc.PhysicalAddress = (DWORD)(POINTER_TYPE)dest;

            DWORD oldProtect;
            VirtualProtect(dest, sizeOfData, PAGE_EXECUTE_READWRITE, &oldProtect);
        }
    }
}

void PELoader::Relocate()
{
    uint32_t locationDelta = static_cast<uint32_t>(_newNTHeader->OptionalHeader.ImageBase - _originalNTHeader->OptionalHeader.ImageBase);
    if (locationDelta != 0)
    {
        PIMAGE_DATA_DIRECTORY directory = GetHeaderDictionary(IMAGE_DIRECTORY_ENTRY_BASERELOC);

        if (directory->Size > 0)
        {
            PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(_newNTHeader->OptionalHeader.ImageBase + directory->VirtualAddress);
            while (relocation->VirtualAddress > 0)
            {
                uint8_t *dest = (uint8_t*)(_newNTHeader->OptionalHeader.ImageBase + relocation->VirtualAddress);
                uint16_t *relInfo = (uint16_t*)((uint8_t*)relocation + sizeof(IMAGE_BASE_RELOCATION));

                for (uint32_t i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, relInfo++)
                {
                    int32_t type, offset = 0;

                    type = *relInfo >> 12;
                    offset = *relInfo & 0xfff;
                    if (type == IMAGE_REL_BASED_ABSOLUTE)
                    {
                    } else if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        *(uint32_t *)((char*)dest + offset) += locationDelta;
                    }
                }

                relocation = (PIMAGE_BASE_RELOCATION)(((int8_t*)relocation) + relocation->SizeOfBlock);
            }
        }
    }
}