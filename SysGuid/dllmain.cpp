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

            char* strUuidPos = strUuid;

            // The UUID stored in the BIOS is arranged in a different order than
            // GUIDs are usually displayed, so we switch that around when building
            // the return string.
            snprintf(strUuidPos, 25, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-",
                dmi_data[3], dmi_data[2], dmi_data[1], dmi_data[0],
                dmi_data[5], dmi_data[4],
                dmi_data[7], dmi_data[6],
                dmi_data[8], dmi_data[9]);

            strUuidPos += 24;
            for (int i = 10; i < 16; i++)
            {
                snprintf(strUuidPos, 3, "%02X", dmi_data[i]);
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