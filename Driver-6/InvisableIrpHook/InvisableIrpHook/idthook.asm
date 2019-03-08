EXTERN DispatchTrap:PROC;
.CODE

public Int25Trap
Int25Trap PROC
	
	add rsp,10h
	popfq
	pop rsp
	sti

	push rax
	push rcx
	pushfq
	
	movzx rax,byte ptr [rsp+18h]

	sub rsp,28h
	mov rcx,rax
	call DispatchTrap
	add rsp,28h

	mov [rsp+18h],rax
	
	popfq
	pop rcx
	pop rax
	
	ret
Int25Trap ENDP

_IdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
_IdtBase ENDP

END