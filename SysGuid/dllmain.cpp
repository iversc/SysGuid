// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>

char strUuid[37] = { 0 };
struct RawSMBIOSData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD    Length;
    BYTE    SMBIOSTableData[];
};

struct dmi_header
{
    BYTE type;
    BYTE length;
    WORD handle;
    BYTE data[1];
};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(dllexport) LPCSTR __stdcall GetSystemGUID()
{
    RawSMBIOSData* SMBiosData = NULL;
    DWORD SMBiosDataSize = 0;
    BYTE* dmi_data = NULL;
    GUID* guid = NULL;

    SMBiosDataSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    SMBiosData = (RawSMBIOSData*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SMBiosDataSize);
    if (!SMBiosData) {
        return NULL;
    }

    if (GetSystemFirmwareTable('RSMB', 0, SMBiosData, SMBiosDataSize) != SMBiosDataSize)
    {
        HeapFree(GetProcessHeap(), 0, SMBiosData);
        return NULL;
    }

    // Go through the BIOS tables
    dmi_data = SMBiosData->SMBIOSTableData;
    while (dmi_data < SMBiosData->SMBIOSTableData + SMBiosData->Length)
    {
        BYTE* NextTable;
        dmi_header* h = (dmi_header*)dmi_data;

        if (h->length < 4)
            break;
        
        // We're looking for a System Information table(type 0x01), 
        // with a length at or above 19h. (Indicates table version >= 2.1,
        // which is when BIOS UUIDs started being supported)
        if (h->type == 0x01 && h->length >= 0x19)
        {
            // UUID starts at offset 0x08
            dmi_data += 0x08;

            guid = (GUID*)dmi_data;
            char* strUuidPos = strUuid;

            snprintf(strUuidPos, 25, "%08X-%04X-%04X-%02X%02X-",
                guid->Data1, guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[1]);

            strUuidPos += 24;
            for (int i = 2; i < 8; i++)
            {
                snprintf(strUuidPos, 3, "%02X", guid->Data4[i]);
                strUuidPos += 2;
            }

            HeapFree(GetProcessHeap(), 0, SMBiosData);
            return strUuid;
        }

        NextTable = dmi_data + h->length;

        // Skips to the end of the current table/structure, which is flagged with a double null byte.
        while (NextTable < SMBiosData->SMBIOSTableData + SMBiosData->Length && (NextTable[0] != 0 || NextTable[1] != 0))
            NextTable++;

        NextTable += 2;
        dmi_data = NextTable;
    }

    HeapFree(GetProcessHeap(), 0, SMBiosData);
    return NULL;
}