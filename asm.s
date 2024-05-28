; nasm -f elf64 -l asm.lst asm.s  ;  ld -s -o asm asm.o

; rdi rsi rdx rcx r8 r9

; gcc -no-pie main.c asm.o

; %d %o %x %b %c %s %%

FALSE equ 0x00000000
TRUE  equ 0xFFFFFFFF

STRING_END equ 0x00
HOT_SYMBOL equ '%'

SIGN_BIT equ 80000000h

LOWEST_SPECIFICATOR     equ 'X'
DELTA_SPECIFICATOR      equ 'x' - 'X'

LowHexOutput    db '0123456789abcdef'
HighHexOutput   db '0123456789ABCDEF'
DecOutput       db '0123456789'
OctOutput       db '01234567'
BinOutput       db '01'

SpecError   db '[UNKNOWN SPECIFICATOR]', 0x00

section .text

global _print                               ; predefined entry point name for ld

_print:         pop rbx                     ; saving return address for CDECL parameters

                push r9
                push r8
                push rcx
                push rdx
                push rsi
                push rdi

                push rbp
                mov  rbp, rsp               ; stack contains parameters (param[i] = [rbp + 8 * i])

                mov rsi, [rbp + 8]
                add rbp, 16                 ; rbp points at the next argument
                call StringOutput

                call ClearBuf

                mov rax, [printed_cnt]

                pop rbp

                pop rdi
                pop rsi
                pop rdx
                pop rcx
                pop r8
                pop r9

                push rbx                    ; return address
                ret


;:================================================
; Prints string with '%' replacements
; Entry: rsi - string pointer, rbp - second argument (all arguments are in stack)
; Exit: rax - printed symbols
; Destr: rbp
;:================================================

StringOutput:   push rbx
                mov rbx, 0                                  ; printed symbols counter

CharLoop:       cmp byte [rsi], STRING_END
                je CharLoopExit

                cmp byte [rsi], HOT_SYMBOL
                jne StandartChar
                call HandleHotSymbol
                add rbx, rax                                ; update counter
                jmp CharLoop

StandartChar:   mov rdi, [rsi]
                call PrintChar
                inc rsi
                inc rbx                                     ; update counter
                jmp CharLoop

CharLoopExit:   mov rax, rbx
                pop rbx
                ret

;:================================================
; Replaces %
; Entry: rbp - current argument, rsi - % pointer in string
; Exit: rax - symbols printed, rbp - next argument pointer in stack,
; Destr:
;:================================================

HandleHotSymbol:    push rsi
                    push rdx

                    inc rsi
                    cmp byte [rsi], '%'
                    jne NotPercent

PercentOut:         mov rdi, '%'                                     ; %% case
                    call PrintChar
                    jmp ExitSwitch                                   ; return
NotPercent:
                    xor rax, rax
                    mov al, byte [rsi]
                    sub rax, LOWEST_SPECIFICATOR

                    cmp rax, DELTA_SPECIFICATOR
                    jg SwitchDefault

                    mov rdx, qword [8*rax + SwitchTable]            ; SWITCH
                    jmp rdx

CharOut:            mov rdi, [rbp]                                  ; %c case
                    add rbp, 8
                    call PrintChar
                    jmp ExitSwitch                                  ; break

StrOut:             mov rdi, [rbp]                                  ; %s case
                    add rbp, 8
                    call PrintString
                    jmp ExitSwitch                                  ; break

LowHexOut:          mov rdi, [rbp]                                  ; %x case
                    add rbp, 8
                    call PrintLowHex
                    jmp ExitSwitch                                  ; break

HighHexOut:         mov rdi, [rbp]                                  ; %X case
                    add rbp, 8
                    call PrintHighHex
                    jmp ExitSwitch                                  ; break

OctOut:             mov rdi, [rbp]                                  ; %o case
                    add rbp, 8
                    call PrintOct
                    jmp ExitSwitch                                  ; break

BinOut:             mov rdi, [rbp]                                  ; %b case
                    add rbp, 8
                    call PrintBin
                    jmp ExitSwitch                                  ; break

DecOut:             mov rdi, [rbp]                                  ; %d case
                    add rbp, 8
                    call PrintDec
                    jmp ExitSwitch                                  ; break

SwitchDefault:      mov rdi, SpecError                              ; default
                    call PrintString
                    jmp ExitSwitch

ExitSwitch:         pop rdx
                    pop rsi
                    add rsi, 2d
                    ret

;:================================================
; Prints hex number (low) in console
; Entry: rdi - hex number
; Exit: rax - symbols printed
; Destr: rcx
;:================================================

PrintLowHex:        push rbx
                    mov cl, 28d                 ; we need to do bitwise shift for 28, to access first 4 bits
                    mov rbx, 0                  ; printed counter
                    mov rdx, FALSE              ; not significant zeros flag

LowHexLoop:         cmp cl, 0d
                    jl ExitLowHexLoop

                    push rdi
                    shr rdi, cl
					and rdi, 0x000F             ; using 1111 bit mask
                    mov rsi, LowHexOutput

					call PrintDigit
                    add rbx, rax

                    pop rdi
                    sub cl, 4d                  ; 4 bits in one digit when we use HEX

                    jmp LowHexLoop

ExitLowHexLoop:     cmp rdx, FALSE
                    jne NotZeroLowHex
                    mov rdi, '0'                ; if all chars are not significant zeros -> print one zero
                    call PrintChar
                    add rbx, rax
NotZeroLowHex:
                    mov rax, rbx
                    pop rbx
                    ret

;:================================================
; Prints hex number (high) in console
; Entry: rdi - hex number
; Exit: rax - symbols printed
; Destr: rcx
;:================================================

PrintHighHex:       push rbx
                    mov cl, 28d                 ; we need to do bitwise shift for 28, to access first 4 bits
                    mov rbx, 0                  ; printed counter
                    mov rdx, FALSE              ; not significant zeros flag

HighHexLoop:        cmp cl, 0d
                    jl ExitHighHexLoop

                    push rdi
                    shr rdi, cl
					and rdi, 0x000F             ; use 1111 bit mask
                    mov rsi, HighHexOutput

					call PrintDigit
                    add rbx, rax

                    pop rdi
                    sub cl, 4d                  ; 4 bits in one digit when we use HEX

                    jmp HighHexLoop

ExitHighHexLoop:    cmp rdx, FALSE
                    jne NotZeroHighHex
                    mov rdi, '0'                ; if all chars are not significant zeros -> print one zero
                    call PrintChar
                    add rbx, rax
NotZeroHighHex:
                    mov rax, rbx
                    pop rbx
                    ret

;:================================================
; Prints oct in console
; Entry: rdi - oct number
; Exit: rax - symbols printed
; Destr: rcx
;:================================================

PrintOct:           push rbx
                    mov cl, 30d                 ; we need to do bitwise shift for 30, to access first 3 bits
                    mov rbx, 0                  ; printed counter
                    mov rdx, FALSE              ; not significant zeros flag

OctLoop:            cmp cl, 0d
                    jl ExitOctLoop

                    push rdi
                    shr rdi, cl
					and rdi, 7                  ; 111 binary mask
                    mov rsi, OctOutput

					call PrintDigit
                    add rbx, rax

                    pop rdi
                    sub cl, 3d                  ; 3 bits in one digit when we use OCT

                    jmp OctLoop

ExitOctLoop:        cmp rdx, FALSE
                    jne NotZeroOct
                    mov rdi, '0'                ; if all chars are not significant zeros -> print one zero
                    call PrintChar
                    add rbx, rax
NotZeroOct:
                    mov rax, rbx
                    pop rbx
                    ret

;:================================================
; Prints bin in console
; Entry: rdi - bin number
; Exit: rax - symbols printed
; Destr: rcx
;:================================================

PrintBin:           push rbx
                    mov cl, 31d                 ; we need to do bitwise shift for 31, to access first bit
                    mov rbx, 0                  ; printed counter
                    mov rdx, FALSE              ; not significant zeros flag

BinLoop:            cmp cl, 0d
                    jl ExitBinLoop

                    push rdi
                    shr rdi, cl
					and rdi, 1                  ; 1 binary mask
                    mov rsi, BinOutput

					call PrintDigit
                    add rbx, rax

                    pop rdi
                    sub cl, 1d                  ; 1 bits in one digit when we use BIN

                    jmp BinLoop

ExitBinLoop:        cmp rdx, FALSE
                    jne NotZeroBin
                    mov rdi, '0'                ; if all chars are not significant zeros -> print one zero
                    call PrintChar
                    add rbx, rax
NotZeroBin:
                    mov rax, rbx
                    pop rbx
                    ret

;:================================================
; Prints dec number in console
; Entry: rdi - dec number
; Exit: rax - symbols printed
; Destr: rcx
;:================================================

PrintDec:           push rbx
                    push rdx
                    push rsi

                    xor rbx, rbx                        ; init printed counter
                    test edi, SIGN_BIT                  ; check if number is negative
                    jz PositiveDec
                    push rdi
                    mov rdi, '-'                        ; print minus if negative
                    call PrintChar
                    add rbx, rax
                    pop rdi

                    neg edi                             ; getting module

PositiveDec:        mov rax, rdi
                    xor rcx, rcx                        ; init digit counter

GetDecDigit:        xor rdx, rdx
                    mov rsi, 10                         ; the basis of the number system
                    div rsi

                    add dl, '0'                         ; turning digit into char
                    push rdx                            ; saving symbol in stack

                    inc rcx

                    test rax, rax
                    jnz GetDecDigit                     ; stop if rax == 0

                    add rbx, rcx

PrintDecDigits:     pop rdi
                    call PrintChar                      ; get digits from stack and print them

                    loop PrintDecDigits

                    mov rax, rbx

                    pop rsi
                    pop rdx
                    pop rbx
                    ret

; --------------------------------------------------
; Prints digit in console
;
; Entry: rdi - digit, rsi - the number system string, rdx - significant zero flag
; Exit: rdx - updates significant zero flag, rax - printed symbols amt
; Destr:
; --------------------------------------------------

PrintDigit		    push rcx

                    mov rax, 0          ; printed symbol flag

                    cmp rdi, 0
                    jne DigitNotZero
                    cmp rdx, FALSE
                    je ExitDigitPrint

DigitNotZero:       mov rdx, TRUE
                    add rsi, rdi
                    mov rdi, [rsi]
                    call PrintChar

ExitDigitPrint:     pop rcx
					ret

;------------------------------------------------
; Gets string length
;
; Entry: rdi - string adress
; Exit:  rax - string len
; Destr:
;------------------------------------------------

MyStrlen:   push rdi
            push rcx

            mov al, STRING_END       ; COUNT TILL MEET

            xor rcx, rcx
            dec rcx                  ; CX = FFFF

            repne scasb

            not rcx
            sub rcx, 1d

            mov rax, rcx              ; AX = CX

            pop rcx
            pop rdi
            ret

;------------------------------------------------
; Prints string
;
; Entry: rdi - string adress
; Exit: rax - symbols printed
; Destr:
;------------------------------------------------

PrintString:    push rbx

                call MyStrlen
                mov rcx, rax
                mov rbx, rdi

                push rax

PrintStrChar:   push rcx
                mov rdi, [rbx]
                call PrintChar
                inc rbx
                pop rcx
                dec rcx
                cmp rcx, 0
                jne PrintStrChar

                pop rax

                pop rbx
                ret

;------------------------------------------------
; Prints char
;
; Entry: rdi - char
; Exit: rax - symbols printed
; Destr:
;------------------------------------------------

PrintChar:      push rdx
                push rbx
                push rcx
                push rsi

                mov [CharBuf], rdi

                mov rsi, CharBuf
                call InsertInBuf

                pop rsi
                pop rcx
                pop rbx
                pop rdx
                ret

;------------------------------------------------
; Inserts character in buffer
;
; Entry: rsi - character pointer
; Exit:
; Destr:
;------------------------------------------------

InsertInBuf:    push rcx
                push rbx

                mov rbx, [curr_buf_size]                    ; rbx = buff size

                mov cl, byte [rsi]                          ; cl = character ASCII
                mov byte [BUFFER + rbx], cl                 ; move char ASCII to temporary buffer
                inc qword [curr_buf_size]                   ; increase buffer size

                cmp cl, 10d                                 ; checking if symbol is a new line

                jne NotNewLine

                call ClearBuf
                jmp InsertBufExit

NotNewLine:

                cmp rbx, BUF_LEN - 1                        ; because of increase before we need to compare with BUF_LEN-1
                jl  NoBuffOverflow

                call ClearBuf

NoBuffOverflow:

InsertBufExit:  pop rbx
                pop rcx
                ret


;------------------------------------------------
; Drops all symbols from buffer in output
;
; Entry:
; Exit:
; Destr:
;------------------------------------------------

ClearBuf:       push rcx
                push rbx

                mov rsi, BUFFER                             ; print buffer if it is full
                mov rax, 0x01                               ; write64 (rdi, rsi, rdx) ... r10, r8, r9
                mov rdi, 1                                  ; stdout
                mov rdx, [curr_buf_size]                    ; buffer size
                syscall

                mov qword [curr_buf_size], 0                ; buf size = 0
                add [printed_cnt], rax                      ; update counter

                pop rbx
                pop rcx
                ret




align 8
SwitchTable:
                                    dq HighHexOut
        times ('b' - 'X' - 1)       dq SwitchDefault
                                    dq BinOut
                                    dq CharOut
                                    dq DecOut
        times ('o' - 'd' - 1)       dq SwitchDefault
                                    dq OctOut
        times ('s' - 'o' - 1)       dq SwitchDefault
                                    dq StrOut
        times ('x' - 's' - 1)       dq SwitchDefault
                                    dq LowHexOut

section .data

CharBuf     dq '0'

printed_cnt dq 0

curr_buf_size dq 0

BUFFER  db '00000000000000000000000000000000'
BUF_LEN equ $ - BUFFER



