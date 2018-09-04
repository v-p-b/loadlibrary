; hacking this together was less annoying than dealing with 
; calling convention declarations

global ASM_pe_read_string_ex 

;
; __cdecl calling convention
;
ASM_pe_read_string_ex:
	push ebp
	mov ebp, esp

	mov eax, dword [ebp+0x8]	; function pointer we are calling
	mov ecx, [ebp+0xc]    		; set up parameter

	push dword [ebp+0x18]		; set up parameter
	push dword [ebp+0x14] 		; set up parameter (QWORD high)
	push dword [ebp+0x10] 		; set up parameter (QWORD low)

	call eax					; actually call the function

	add esp, 0xc 				; stack cleanup after the call to pe_read_string_ex
	pop ebp
	ret
	
