.model flat, c

.code 

__AsmConstantCondition proc
    xor eax, eax
	jz L_END
	db 0e8h
L_END:
	nop
    ret
__AsmConstantCondition endp


__AsmJmpSameTarget proc
	jz L_END
	jnz L_END
	db 0e8h
L_END:
	nop
	ret
__AsmJmpSameTarget endp


__AsmImpossibleDisassm proc
	push eax

	mov ax, 05EBh	; db 066h, 0B8h, 0EBh, 005h
	xor eax, eax	; db 033h, 0C0h
	db 074h, 0fah
	db 0e8h			; call

	pop eax
	ret
__AsmImpossibleDisassm endp

; a dummy function
func2 proc arg_0:DWORD
	 mov eax, [arg_0]
	 shl eax, 2
	 pop ebp
	 retn
 func2 endp


__AsmFunctionPointer proc arg_0:DWORD

	LOCAL var_4:DWORD

	push ecx
	push esi
	mov [var_4], offset func2
	push 03h
	call [var_4]
	add esp, 4
	mov esi, eax
	mov eax, [arg_0]
	push eax
	call [var_4]
	add esp, 4
	lea eax, [esi+eax+1]
	pop esi
	mov esp, ebp
	pop ebp
	retn
__AsmFunctionPointer endp

__AsmReturnPointerAbuse proc

	call $+5
	add dword ptr[esp], 5
	retn

	push eax
	mov eax, [ebp+8]
	imul eax, 40h
	pop eax
	retn
__AsmReturnPointerAbuse endp

; another dummy function
func3 proc 
	mov esp, [esp+8]
	ASSUME FS:NOTHING
	mov eax, dword ptr fs:[0]
	ASSUME FS:ERROR
	mov eax, [eax]
	mov eax, [eax]
	ASSUME FS:NOTHING
	mov dword ptr fs:[0], eax
	ASSUME FS:ERROR
	add esp, 8
	pop ebp
	retn
 func3 endp

__AsmSEHMisuse proc
	push ebp
	mov eax, offset func3
	push eax
	ASSUME FS:NOTHING
	push dword ptr fs:[0]
	mov dword ptr fs:[0], esp
	ASSUME FS:ERROR
	xor ecx, ecx
	div ecx
	call func2
	retn
__AsmSEHMisuse endp

end
