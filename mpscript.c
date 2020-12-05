//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <iconv.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <err.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "log.h"
#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"

extern HF_ITER(uint8_t** buf, size_t* len);

const char header[] =
    "function log(msg) { parseFloat('__log: ' + msg); }\n"
    "function dump(obj) { for (i in obj) { log(i); log('\\t' + obj[i]); }; }\n";
const char footer[] = {
    #include "script.h" // Generated by Makefile
    0,                  // String terminator
};

DWORD (* __rsignal)(PHANDLE KernelHandle, DWORD Code, PVOID Params, DWORD Size);

double JavaScriptLog(const char *nptr, char **endptr)
{
    if (strncmp(nptr, "__log: ", 7) == 0) {
        LogMessage("%s", nptr + 7);
        return 0;
    }
    return strtod(nptr, endptr);
}

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    return 0;
}

static DWORD ReadStream(PVOID this, QWORD Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    memcpy(Buffer, this + Offset, *SizeRead = MIN(strlen(this+Offset), Size));
    return TRUE;
}

static DWORD GetStreamSize(PVOID this, PQWORD FileSize)
{
    *FileSize = strlen(this);
    return TRUE;
}

int main(int argc, char **argv, char **envp)
{
    PVOID StrtodPtr;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;
    HANDLE KernelHandle;
    SCAN_REPLY ScanReply;
    BOOTENGINE_PARAMS BootParams;
    SCANSTREAM_PARAMS ScanParams;
    STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;
    struct pe_image image = {
        .entry  = NULL,
        .name   = "engine/mpengine.dll",
    };

    // Load the mpengine module.
    if (pe_load_library(image.name, &image.image, &image.size) == false) {
        return 2;
    }

    // Handle relocations, imports, etc.
    link_pe_images(&image, 1);

    // Fetch the headers to get base offsets.
    DosHeader   = (PIMAGE_DOS_HEADER) image.image;
    PeHeader    = (PIMAGE_NT_HEADERS)(image.image + DosHeader->e_lfanew);

    // Load any additional exports.
    if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "engine/mpengine.map")) {
        LogMessage("A map file is required to intercept interpreter output. See documentation.");
    }

    if (get_export("__rsignal", &__rsignal) == -1) {
        LogMessage("Cannot resolve mpengine!__rsignal, cannot continue");
        return 3;
    }

    if (get_export("_strtod", &StrtodPtr) != -1) {
        insert_function_redirect(StrtodPtr, JavaScriptLog, HOOK_REPLACE_FUNCTION);
    } else {
        LogMessage("Unable to hook output (missing or incomplete map?), but input might still work. See documentation.");
    }

    // Call DllMain()
    image.entry((PVOID) 'MPEN', DLL_PROCESS_ATTACH, NULL);

    ZeroMemory(&BootParams, sizeof BootParams);
    ZeroMemory(&EngineInfo, sizeof EngineInfo);
    ZeroMemory(&EngineConfig, sizeof EngineConfig);

    BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
    BootParams.Attributes    = BOOT_ATTR_NORMAL;
    BootParams.SignatureLocation = L"engine";
    BootParams.ProductName = L"Legitimate Antivirus";
    EngineConfig.QuarantineLocation = L"quarantine";
    EngineConfig.Inclusions = L"*.*";
    EngineConfig.EngineFlags = 1 << 1;
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;

    LogMessage("Please wait, initializing engine...");

    if (__rsignal(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof BootParams) != 0) {
        LogMessage("__rsignal(RSIG_BOOTENGINE) returned failure, missing definitions?");
        LogMessage("Make sure the VDM files and mpengine.dll are in the engine directory");
        return 4;
    }

    ZeroMemory(&ScanParams, sizeof ScanParams);
    ZeroMemory(&ScanDescriptor, sizeof ScanDescriptor);
    ZeroMemory(&ScanReply, sizeof ScanReply);

    ScanParams.Descriptor        = &ScanDescriptor;
    ScanParams.ScanReply         = &ScanReply;
    ScanReply.EngineScanCallback = EngineScanCallback;
    ScanReply.field_C            = 0x7fffffff;
    ScanDescriptor.Read          = ReadStream;
    ScanDescriptor.GetSize       = GetStreamSize;

    LogMessage("Try log(msg) or dump(obj), mp.getAttribute() can query scan state booleans.");
    while (true) {
        CHAR *InputBuf;
        size_t hf_len;

        HF_ITER(&InputBuf,&hf_len); // InputBuf is free'd by HonggFuzz

		if (InputBuf) {
            CHAR *EscapeBuf = calloc(strlen(InputBuf) + 1, 3);
            CHAR *p = EscapeBuf;

            if (!EscapeBuf)
                break;

            // This is probably not correct.
            for (size_t i = 0; InputBuf[i]; i++) {
               if (InputBuf[i] == '%') {
                   *p++ = '%'; *p++ = '2'; *p++ = '5';
               } else if (InputBuf[i] == '"') {
                   *p++ = '%'; *p++ = '2'; *p++ = '2';
               } else if (InputBuf[i] == '\\') {
                   *p++ = '%'; *p++ = '5'; *p++ = 'c';
               } else if (InputBuf[i] == '\n') {
                   *p++ = ' ';
               } else {
                   *p++ = InputBuf[i];
               }
            }

            if (asprintf((PVOID) &ScanDescriptor.UserPtr,
                         "%s\ntry{log(eval(unescape(\"%s\")))} catch(e) { log(e); }\n%s",
                         header,
                         EscapeBuf,
                         footer) == -1) {
                err(EXIT_FAILURE, "memory allocation failure");
            }
            free(EscapeBuf);
        } else {
            break;
        }


        if (__rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams) != 0) {
            LogMessage("__rsignal(RSIG_SCAN_STREAMBUFFER) returned failure, file unreadable?");
            return 1;
        }

        free(ScanDescriptor.UserPtr);
    }

    return 0;
}
