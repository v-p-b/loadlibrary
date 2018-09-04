#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "peloader/winnt_types.h"
#include "peloader/util.h"


void SetHooks(const uint32_t ImageBase, const uint32_t ImageSize);

//Typedef for templated Parameters<> calls
typedef uint32_t __thiscall(* ParametersCall)(void * params, void * v);
ParametersCall Parameters1;

// address of pe_read_string_ex
uint32_t * FP_pe_read_string_ex; 
//struct to store offsets
typedef struct _RVAS {
    char * MPVERNO;
    uint32_t RVA_Parameters1;
    uint32_t RVA_pe_read_string_ex;
    uint32_t RVA_FP_OutputDebugStringA;
} RVAS, *PRVAS;

