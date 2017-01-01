/*  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  2016.09.02  first version
 *              1. support exe and dll
 *              2. support i386 and x86_64
 *  2016.10.15  fix none import crash
 *  2016.10.28  add controllable command line flags
 *  2016.11.01  fixed: not support multi-input files
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <windows.h>

#include "pygetopt.h"

#define VERSION     "2016.11.01"

typedef struct pedump_t {
    IMAGE_DOS_HEADER        DosHeader;
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    union {
    IMAGE_OPTIONAL_HEADER32 Header32;
    IMAGE_OPTIONAL_HEADER64 Header64;
    } OptionalHeader;
    PIMAGE_SECTION_HEADER   sections;
}pedump_t;

void print_pe_brief(const pedump_t* pe)
{
    time_t t;
    struct tm tm;
    char timestamp[256];

    if (pe->OptionalHeader.Header32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("PE32 ");
    } else if (pe->OptionalHeader.Header64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("PE32+ ");
    }

    if (pe->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        printf("executable ");
    }

    if (pe->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        printf("(DLL) ");
    }

    if (pe->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) {
        printf("(32bits) ");
    }

    if (pe->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        if (pe->OptionalHeader.Header32.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
            printf("(console) ");
        } else if (pe->OptionalHeader.Header32.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
            printf("(GUI) ");
        } else {
            printf("(Subsystem:0x%04x) ", pe->OptionalHeader.Header32.Subsystem);
        }
    } else {
        if (pe->OptionalHeader.Header64.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
            printf("(console) ");
        } else if (pe->OptionalHeader.Header64.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
            printf("(GUI) ");
        } else {
            printf("(Subsystem:0x%04x) ", pe->OptionalHeader.Header64.Subsystem);
        }
    }

    switch (pe->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:   printf("i386"); break;
        case IMAGE_FILE_MACHINE_AMD64:  printf("x86_64"); break;
        default: printf(" Machine:0x%04x", pe->FileHeader.Machine);
    }

    t = (time_t)pe->FileHeader.TimeDateStamp;
    tm = *localtime(&t);

    strftime(timestamp, sizeof(timestamp), " (%a %b %d %H:%M:%S %Y)", &tm);
    printf("%s", timestamp);

    printf("\n");
}

uint64_t rva2offset(const pedump_t* pe, uint64_t rva)
{
    int i;

    for (i = pe->FileHeader.NumberOfSections - 1;i >= 0;i--) {
        if (rva >= pe->sections[i].VirtualAddress) {
            return rva - pe->sections[i].VirtualAddress + pe->sections[i].PointerToRawData;
        }
    }

    return 0;
}

int parse_import_directory(const pedump_t* pe, const uint8_t* buf, uint64_t length, int verbose)
{
    IMAGE_DATA_DIRECTORY dir;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    PIMAGE_THUNK_DATA32 thunk32;
    PIMAGE_THUNK_DATA64 thunk64;
    PIMAGE_IMPORT_BY_NAME function;
    uint64_t offset;

    if (pe->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        dir = pe->OptionalHeader.Header32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        dir = pe->OptionalHeader.Header64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if ((dir.VirtualAddress == 0) || (dir.Size == 0)) {
        return 0;
    }

    offset = rva2offset(pe, dir.VirtualAddress);
    imp = (PIMAGE_IMPORT_DESCRIPTOR)(buf + offset);

    for (;;imp++) {
        if (!imp->OriginalFirstThunk &&
            !imp->TimeDateStamp &&
            !imp->ForwarderChain &&
            !imp->Name &&
            !imp->FirstThunk)
        {
            break;
        }

        printf("  Import %s\n", (char*)(buf + rva2offset(pe, imp->Name)));
        if (!verbose) {
            continue;
        }

        printf("    Hint     Name\n");
        printf("    -------- --------\n");
        offset = rva2offset(pe, imp->OriginalFirstThunk);
        if (pe->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            for (thunk32 = (PIMAGE_THUNK_DATA32)(buf + offset);thunk32->u1.Ordinal;thunk32++) {
                if (thunk32->u1.Ordinal >> 31) {
                    printf("    0x%04x   (NONAME)\n", (int)(thunk32->u1.Ordinal & 0xFFFFu));
                    continue;
                }

                offset = rva2offset(pe, thunk32->u1.Ordinal);
                function = (PIMAGE_IMPORT_BY_NAME)(buf + offset);
                printf("    0x%04x   %s\n", (int)(function->Hint), function->Name);
            }


        } else {
            for (thunk64 = (PIMAGE_THUNK_DATA64)(buf + offset);thunk64->u1.Ordinal;thunk64++) {
                if (thunk64->u1.Ordinal >> 63) {
                    printf("    0x%04x   (NONAME)\n", (int)(thunk64->u1.Ordinal & 0xFFFFu));
                    continue;
                }

                offset = rva2offset(pe, thunk64->u1.Ordinal);
                function = (PIMAGE_IMPORT_BY_NAME)(buf + offset);
                printf("    0x%04x   %s\n", (int)(function->Hint), function->Name);
            }
        }

        printf("\n");
    }

    return 1;
}


int parse_export_directory(const pedump_t* pe, const uint8_t* buf, uint64_t length, int verbose)
{
    IMAGE_DATA_DIRECTORY dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    uint32_t* func_table;
    uint16_t* hint_table;
    uint32_t* name_table;
    uint64_t offset;
    int i;
    int j;

    if (pe->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        dir = pe->OptionalHeader.Header32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        dir = pe->OptionalHeader.Header64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if ((dir.VirtualAddress == 0) || (dir.Size == 0)) {
        return 0;
    }

    offset = rva2offset(pe, dir.VirtualAddress);
    exp = (PIMAGE_EXPORT_DIRECTORY)(buf + offset);

    offset = rva2offset(pe, exp->AddressOfFunctions);
    func_table = (uint32_t*)(buf + offset);

    printf("  Export %s\n", (char*)(buf + rva2offset(pe, exp->Name)));
    if (!verbose) {
        return 1;
    }

    printf("    Ordinal  Hint     Entry      Name\n");
    printf("    -------- -------- ---------- --------\n");
    for (i = 0;i < exp->NumberOfFunctions;i++) {
        offset = rva2offset(pe, exp->AddressOfNameOrdinals);
        hint_table = (uint16_t*)(buf + offset);
        for (j = 0;j < exp->NumberOfNames;j++) {
            if (hint_table[j] == i) {
                break;
            }
        }

        //Ordinal is index from Functions table,
        //Hit is index from Names table.

        if (j == exp->NumberOfNames) {
            printf("    0x%04x   0x%04x   0x%08x (NONAME)\n",
                    (int)(exp->Base + i), j, (int)(rva2offset(pe, func_table[i])));
            continue;
        }

        offset = rva2offset(pe, exp->AddressOfNames);
        name_table = (uint32_t*)(buf + offset);
        offset = rva2offset(pe, name_table[j]);
        printf("    0x%04x   0x%04x   0x%08x %s\n",
                (int)(exp->Base + i), j, (int)(rva2offset(pe, func_table[i])), (char*)(buf + offset));
    }

    return 1;
}

int parse_pe(const uint8_t* buf, uint64_t length,
        int show_imports, int show_exports, int verbose)
{
    pedump_t pe;
    int i;
    uint32_t offset;

    if (length < sizeof(IMAGE_DOS_HEADER)) {
        printf("Error: file too small!\n");
        return -1;
    }
    memcpy(&pe.DosHeader, buf, sizeof(IMAGE_DOS_HEADER));
    if (pe.DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: not dos signature!\n");
        return -1;
    }
    if (length < pe.DosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) {
        printf("Error: file too small!\n");
        return -1;
    }

    offset = pe.DosHeader.e_lfanew;

    memcpy(&pe.Signature, buf + offset, sizeof(DWORD));
    offset += sizeof(DWORD);

    memcpy(&pe.FileHeader, buf + offset, sizeof(IMAGE_FILE_HEADER));
    offset += sizeof(IMAGE_FILE_HEADER);

    if (pe.Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: not nt signature!\n");
        return -1;
    }

    if (pe.FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        memcpy(&pe.OptionalHeader.Header32, buf + offset, sizeof(IMAGE_OPTIONAL_HEADER32));
    } else if (pe.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        memcpy(&pe.OptionalHeader.Header64, buf + offset, sizeof(IMAGE_OPTIONAL_HEADER32));
    } else {
        printf("Error: not support machine 0x%04x!\n", pe.FileHeader.Machine);
        return -1;
    }
    offset += pe.FileHeader.SizeOfOptionalHeader;

    pe.sections = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * pe.FileHeader.NumberOfSections);
    memcpy(pe.sections, buf + offset, sizeof(IMAGE_SECTION_HEADER) * pe.FileHeader.NumberOfSections);

    print_pe_brief(&pe);

    if (verbose && show_imports && show_exports) {
        printf("  Sections\n");
        printf("    %-10s %-10s\n", "RVA", "OFFSET");
        printf("    %-10s %-10s\n", "----------", "----------");
        for (i = 0;i < pe.FileHeader.NumberOfSections;i++) {
            printf("    0x%08x 0x%08x\n",
                    (int)pe.sections[i].VirtualAddress,
                    (int)pe.sections[i].PointerToRawData);
        }
        printf("\n");
    }

    if (show_imports) {
        parse_import_directory(&pe, buf, length, verbose);
    }
    if (show_exports) {
        parse_export_directory(&pe, buf, length, verbose);
    }

    free(pe.sections);
    pe.sections = NULL;

    return 0;
}

int pedump(const char* fn, int show_imports, int show_exports, int verbose)
{
    HANDLE hfile;
    HANDLE hmap;

    DWORD size_high;
    DWORD size_low;

    uint64_t length;
    uint8_t* buf;

    hfile = CreateFile(
        fn,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        printf("CreateFile, GetLastError() = %u\n", (uint32_t)GetLastError());
        return -1;
    }

    size_low = GetFileSize(hfile, &size_high);
    ((uint32_t*)&length)[0] = size_low;
    ((uint32_t*)&length)[1] = size_high;

    hmap = CreateFileMapping(hfile,
        NULL,
        PAGE_READONLY,
        0/*dwMaximumSizeHigh*/,
        0/*dwMaximumSizeLow*/,
        NULL/*lpFileName*/);
    if (hmap == INVALID_HANDLE_VALUE) {
        printf("CreateFile, GetLastError() = %u\n", (uint32_t)GetLastError());
        goto L_ERROR0;
    }

    buf = (uint8_t*)MapViewOfFile(
        hmap,
        FILE_MAP_READ,
        0/*dwFileOffsetHigh*/,
        0/*dwFileOffsetLow>*/,
        (size_t)length);
    if (buf == NULL) {
        printf("CreateFile, GetLastError() = %u\n", (uint32_t)GetLastError());
        goto L_ERROR1;
    }

    printf("%s: ", fn);
    parse_pe(buf, length, show_imports, show_exports, verbose);

    UnmapViewOfFile(buf);
    buf = NULL;

L_ERROR1:
    CloseHandle(hmap);
    hmap = INVALID_HANDLE_VALUE;

L_ERROR0:
    CloseHandle(hfile);
    hfile = INVALID_HANDLE_VALUE;

    return 0;
}

void print_usage(char* fn)
{
    printf("Version: %s\n", VERSION);
    printf("Build  : %s %s\n", __DATE__, __TIME__);
    printf("Usage  : %s [option] files\n", fn);
    printf("  %-26s %s\n",  "-v, --verbose", "show import and export details");
    printf("  %-26s %s\n",  "--ni", "do not show import");
    printf("  %-26s %s\n",  "--ne", "do not show export");
    printf("  %-26s %s\n",  "--no", "do not show export");
    printf("  %-26s %s\n",  "--vi", "show import");
    printf("  %-26s %s\n",  "--ve", "show export");
    printf("  %-26s %s\n",  "--vo", "show export");
}

int main(int argc, char* argv[])
{
    pygetopt_t* cfg = NULL;
    const char* fmt = "v";
    const char* lfmt[] = {
        "verbose",
        "ni",
        "ne",
        "no",
        "vi",
        "ve",
        "vo",
        NULL,
    };
    int i;
    int show_exports = 1;
    int show_imports = 1;
    int verbose = 0;

    int no_exports   = 0;
    int no_imports   = 0;
    int verb_imports = 0;
    int verb_exports = 0;

    if (argc == 1) {
        goto L_ERROR0;
    }
    cfg = pygetopt_parse(argc-1, argv+1, fmt, lfmt);
    if (cfg == NULL) {
        goto L_ERROR1;
    }
    if (cfg->args_n == 0) {
        goto L_ERROR2;
    }

    for (i = 0;i < cfg->opts_n;i++) {
        if (strcmp(cfg->opts[i].key, "-v") == 0) {
            verbose = 1;
        } else if (strcmp(cfg->opts[i].key, "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(cfg->opts[i].key, "--ni") == 0) {
            no_imports = 1;
        } else if (strcmp(cfg->opts[i].key, "--ne") == 0) {
            no_exports = 1;
        } else if (strcmp(cfg->opts[i].key, "--no") == 0) {
            no_exports = 1;
        } else if (strcmp(cfg->opts[i].key, "--vi") == 0) {
            verb_imports = 1;
        } else if (strcmp(cfg->opts[i].key, "--ve") == 0) {
            verb_exports = 1;
        } else if (strcmp(cfg->opts[i].key, "--vo") == 0) {
            verb_exports = 1;
        }
    }

    if (verbose) {
        show_imports = 1;
        show_imports = 1;
    } else if (verb_imports || verb_exports) {
        show_imports = verb_imports && !no_imports;
        show_exports = verb_exports && !no_exports;
        verbose = 1;
    } else {
        if (no_imports) {
            show_imports = 0;
        }
        if (no_exports) {
            show_exports = 0;
        }
    }

    for (i = 0;i < cfg->args_n;i++) {
        pedump(cfg->args[i], show_imports, show_exports, verbose);
    }

    pygetopt_destroy(cfg);
    cfg = NULL;
    return 0;

L_ERROR2:
    pygetopt_destroy(cfg);
    cfg = NULL;

L_ERROR1:
    printf("\n");

L_ERROR0:
    print_usage(argv[0]);

    return -1;
}


