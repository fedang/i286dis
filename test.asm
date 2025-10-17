org 0x100
bits 16

nop
clc
cli
std
cbw
cwd

jmp short label1
label1:
nop
label2:
nop

loop label2

mov al, 0x12
mov ax, 0x1234
add al, 0x34
add ax, 0x5678

mov bx, ax
mov [si], al
add ax, bx
add [di], cx

add byte [bx+si], 0x99
sub byte [bp+di], 0x88

rol al, 1
ror ax, 1
shl bx, 1
shr cx, 1

hlt
