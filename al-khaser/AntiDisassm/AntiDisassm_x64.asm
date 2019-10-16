
.code 

__AsmConstantCondition proc
    xor rax, rax
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
	push rax

	mov ax, 05EBh	; db 066h, 0B8h, 0EBh, 005h
	xor eax, eax	; db 033h, 0C0h
	db 074h, 0fah
	db 0e8h			; call

	pop rax
	ret
__AsmImpossibleDisassm endp

; a dummy function
func2 proc
	mov rax, r8
	shl rax, 2
	ret
 func2 endp


__AsmFunctionPointer proc
	push rax
	push rcx
	push rsi
	mov rcx, offset func2
	mov r8, 02h
	call rcx
	mov rsi, rax
	mov r8, 03h
	call rcx
	lea rax, [rsi+rax+1]
	pop rsi
	pop rcx
	pop rax
	ret
__AsmFunctionPointer endp


__AsmReturnPointerAbuse proc
	call $+5
	add qword ptr[rsp], 6
	ret

	push rax
	mov rax, rcx
	imul rax, 40h
	pop rax
	ret
__AsmReturnPointerAbuse endp


end
