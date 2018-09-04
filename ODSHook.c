#include "ODSHook.h"


// This structure contains relative virtual addresses for three key addresses
// we need to make the OutputDebugStringA trick work. These addresses are relative
// from the base of mpengine.dll
//
// Note: these RVAs are specific to the 6/25/2018 mpengine.dll release
// MD5: e95d3f9e90ba3ccd1a4b8d63cbd88d1b
RVAS RVAs_June_2018 = {

    .MPVERNO = "MP_9_4_2018",

    // This function gets the parameter passed a 1 parameter emulated 
    // function from the pe_vars_t * passed to every emulated function
    .RVA_Parameters1 = 0x4d07f5,

    // This function translates the virtual memory address of a string to a 
    // native char * that we can print
    .RVA_pe_read_string_ex = 0x3ee353,

    // The address of the function pointer to KERNEL32_DLL_OuputDebugStringA
    // in the g_syscalls table. It should look something like this:
    /*
    .text:5A11A0D8  dd offset ?KERNEL32_DLL_CopyFileWWorker@@YAXPAUpe_vars_t@@@Z ; KERNEL32_DLL_CopyFileWWorker(pe_vars_t *)
    .text:5A11A0DC  dd 0B27D5174h
    .text:5A11A0E0  dd offset ?KERNEL32_DLL_OutputDebugStringA@@YAXPAUpe_vars_t@@@Z ; KERNEL32_DLL_OutputDebugStringA(pe_vars_t *)
    .text:5A11A0E4  dd 0B28014BBh
    .text:5A11A0E8  dd offset ?NTDLL_DLL_NtGetContextThread@@YAXPAUpe_vars_t@@@Z ; NTDLL_DLL_NtGetContextThread(pe_vars_t *)
    .text:5A11A0EC  dd 0B363A610h
    */
    .RVA_FP_OutputDebugStringA = 0x1b528L,
};

//
// Call into pe_read_string_ex to translate the virtual address of a
// string in the emulated address space to a real char * that we can 
// interact with. Len value returns the length of the string
//
// Due to an annoying calling convention (fastcall but with a 64-bit 
// value in one of the first 2 arguments), trampolining through assembly 
// is easier than setting GCC compiler attributes 
//
// __cdecl calling convention (implicitly on GCC, but if you have any problems
// linking or running, double check this)
char * ASM_pe_read_string_ex(uint32_t * , void *, uint64_t, uint32_t *);

static char * GetString(void * V, uint64_t Param, uint32_t * Len)
{
    //trampoline through assembly with wierd calling convention
    return ASM_pe_read_string_ex(FP_pe_read_string_ex, V, Param, Len);
}

//
// Hook for OutputDebugStringA - just print a string to stdout
//
static void __cdecl KERNEL32_DLL_OutputDebugStringA_hook(void * v)
{
    uint64_t Params[1] = {0};
    char * str = NULL;
    DWORD len = 0;

    // void * v is a pe_vars_t *, a huge structure containing all 
    // the information for given emulation session. We don't have
    // the full structure definition, so we just treat it as a void *
    printf("[+] OutputDebugStringA(pe_vars_t * v = 0x%p)\n", v);

    // use Defender's internal Parameters<1>::Parameters<1> function 
    // to retrieve the one parameter passed to kernel32!OutputDebugStringA
    // inside the emulator. This will give us the virtual address of a char *
    // inside the emulator
    Parameters1(Params, v);

    // print out the virtual address of the char * argument
    printf("[+] Params[1]:\t0x%llx\n", Params[0]);

    // use Defender's internal pe_read_string_ex function to translate a 
    // virtual address to a real address we can interact with
    str = GetString(v, Params[0], &len);

    // now that we finally have a real pointer we can interact with, print
    // the string out to stdout
    printf("[+] OutputDebugStringA: \"%s\"\n", str);

    return;
}

//
// Set hooks and calculate offsets for functions we will call
//
void SetHooks(const uint32_t ImageBase, const uint32_t ImageSize)
{
    uint32_t * pOutputDebugStringA;

    printf("[+] MpEngine.dll base at 0x%x\n", ImageBase);
    printf("[+] Setting hooks and resolving offsets\n");

    // resolve the address of Parameters<1>::Parameters<1>, we will be calling it
    Parameters1 = (void*)((unsigned char*)ImageBase + RVAs_June_2018.RVA_Parameters1);
    printf("[+] Parameters<1>::Parameters<1>\tRVA: 0x%06x\tAddress: %p\n", RVAs_June_2018.RVA_Parameters1, Parameters1);

    // resolve the address of pe_read_string_ex, we will be calling it
    FP_pe_read_string_ex = (void*)((unsigned char*)ImageBase + RVAs_June_2018.RVA_pe_read_string_ex);
    printf("[+] pe_read_string_ex:\t\t\tRVA: 0x%06x\tAddress: %p\n", RVAs_June_2018.RVA_pe_read_string_ex, FP_pe_read_string_ex);

    // resolve the address of a function pointer to KERNEL32_DLL_OutputDebugStringA, we are replacing it
    pOutputDebugStringA = (void*)((unsigned char*)ImageBase + RVAs_June_2018.RVA_FP_OutputDebugStringA);
    printf("[+] OutputDebugStringA FP:\t\tRVA: 0x%06x\tAddress: 0x%x\n", RVAs_June_2018.RVA_FP_OutputDebugStringA, *(pOutputDebugStringA));
    *pOutputDebugStringA = (uint32_t)KERNEL32_DLL_OutputDebugStringA_hook;
    printf("[+] OutputDebugStringA FP replaced: \t0x%x\n", *(pOutputDebugStringA));


    printf("[+] Done setting hooks and resolving offsets!\n");
}
