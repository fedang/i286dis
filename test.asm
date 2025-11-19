org 0x100
bits 16

mov ax, [0x1234]
mov [0x2345], bx
mov es:[0x2345], bx

imul ax, [bx+0x30], 10

nop
clc
cli
std
cbw
cwd

push si
pushf
pop ax
inc si
rep movsb

enter 2, 0

leave

jmp short label1
label1:
nop
label2:
nop

int3

loop label2

mov al, [0x1234]

lock xchg al, bl

int3
nop
nop
nop

mov al, 0x12
mov ax, 0x1234
add al, 0x34
add ax, 0x5678

mov bx, ax
mov [si], al

mov [bx+di+19], al

add ax, bx
add [di], cx

add byte [bx+si], 0x99
sub byte [bp+di], 0x88

cmp ax, 10
jz sus

nop

sus:

rol al, 1
ror ax, 1
shl bx, 1
shr cx, 1

hlt
jmp skip

val1 dw 0x1234
val2 dw 0x5678

skip:

mov cx, [val1]

inc word [val1]     ; FF /0
dec word [val2]     ; FF /1
call word [val1]    ; FF /2
push word [val1]
jmp word [val2]     ; FF /4
