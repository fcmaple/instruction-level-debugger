# instruction-level-debugger
I implement a simple instruction-level debugger that allow a user to bebug a program interactively at the assembly instruction level. 

## How to use
```shell=
make
./sdb bin/[program]
```

## Specification
Unlike `gdb` and `lldb` , the debugger launches the target program when the debugger starts. 
The program should stop at the entry point, waiting for the user’s `cont` or `si` commands. 

When the program is launched, the debugger should display the name of the executable and the entry point address. Before waiting for the user’s input, the debugger should disassemble 5 instructions starting from the current program counter (rip). The detail requirement is described in the following paragraph.

```shell=
** program './hello64' loaded. entry point 0x4000b0
      4000b0: b8 04 00 00 00                  mov       eax, 4
      4000b5: bb 01 00 00 00                  mov       ebx, 1
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
(sdb) 
```

### Disassemble

When returning from execution, the debugger should disassemble 5 instruction starting from the current program counter. The address of the 5 instructions should be within the range of the text section specified in the ELF file. each information of instructions below :
1. address, eg. `40000b0`
2. raw instructions in grouping of 1 byte, eg. `b8 04 00 00 00`
3. mnemonic, eg. `mov`
4. operands of the instruction, eg. `eax, 4`

#### Example :
```shell=
(sdb) si
      4000c4: cd 80                           int       0x80
      4000c6: b8 01 00 00 00                  mov       eax, 1
      4000cb: bb 00 00 00 00                  mov       ebx, 0
      4000d0: cd 80                           int       0x80
      4000d2: c3                              ret       
(sdb) si
hello, world!
      4000c6: b8 01 00 00 00                  mov       eax, 1
      4000cb: bb 00 00 00 00                  mov       ebx, 0
      4000d0: cd 80                           int       0x80
      4000d2: c3                              ret       
** the address is out of the range of the text section.
(sdb) 
(sdb) si
      4000cb: bb 00 00 00 00                  mov       ebx, 0
      4000d0: cd 80                           int       0x80
      4000d2: c3                              ret       
** the address is out of the range of the text section.
```

### Step instruction
Command : `si` 
When the user use `si` command, the target process should execute a single instruction. 
 
#### Example: 
```shell=
(sdb) si 
      4000c4: cd 80                           int       0x80
      4000c6: b8 01 00 00 00                  mov       eax, 1
      4000cb: bb 00 00 00 00                  mov       ebx, 0
      4000d0: cd 80                           int       0x80
      4000d2: c3                              ret       
(sdb) si
hello, world!
      4000c6: b8 01 00 00 00                  mov       eax, 1
      4000cb: bb 00 00 00 00                  mov       ebx, 0
      4000d0: cd 80                           int       0x80
      4000d2: c3                              ret       
** the address is out of the range of the text section. 
(sdb)  
```

### Continue
Command : `cont` 
When the user use `cont` command, the target process should keep running util it terminates or hits a breakpoint. 

#### Example : 
```shell= 
** program './hello64' loaded. entry point 0x4000b0
      4000b0: b8 04 00 00 00                  mov       eax, 4
      4000b5: bb 01 00 00 00                  mov       ebx, 1
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
(sdb) break 0x4000ba
** set a breakpoint at 0x4000ba.
(sdb) cont
** hit a breakpoint at 0x4000ba.
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
      4000c6: b8 01 00 00 00                  mov       eax, 1
      4000cb: bb 00 00 00 00                  mov       ebx, 0
(sdb) cont
hello, world!
** the target program terminated.
``` 
### Breakpoint
Command : `break <address in hexdecimal>` 
When a user use `break <address in hexdecimal>` to set a breakpoint. The target process should stop at the specified address. Then is should print a message about the state of the process. 

#### implement detail
When setting a breakpoint.
1. Use `ptrace(PEEKTEXT)` to see and record the raw instruction. 
2. Modify the original instrctions to `0xcc`. 
3. Use `ptrace(POKETEXT)` to modify the raw instruction on the target process.

#### Example:
```shell=
** program './hello64' loaded. entry point 0x4000b0
      4000b0: b8 04 00 00 00                  mov       eax, 4
      4000b5: bb 01 00 00 00                  mov       ebx, 1
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
(sdb) break 0x4000ba
** set a breakpoint at 0x4000ba.
(sdb) si 
      4000b5: bb 01 00 00 00                  mov       ebx, 1
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
      4000c6: b8 01 00 00 00                  mov       eax, 1
(sdb) si
** hit a breakpoint 0x4000ba.
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
      4000c6: b8 01 00 00 00                  mov       eax, 1
      4000cb: bb 00 00 00 00                  mov       ebx, 0
```



### Timetravel
Command : `anchor`  `timetravel`  
The user can use `anchor` to set the checkpoint, and use `timetravel` to restore the process state. 

#### Implement detail
When user call `anchor` to set the checkpoint. 
1. Record the registers state by using `ptrace(GETREGS)`. 
2. Record the `.bss`,`.text`,`stack` ... all memory of the process. 

When user call `timetravel` to restore the process state. 
1. Reset the memory and registers of the target process. 
2. Reset the all breakpoint to target process. 

#### Example: 
```shell=
** program './hello64' loaded. entry point 0x4000b0
      4000b0: b8 04 00 00 00                  mov       eax, 4
      4000b5: bb 01 00 00 00                  mov       ebx, 1
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
(sdb) anchor
** dropped an anchor
(sdb) break 0x4000cb
** set a breakpoint at 0x4000cb
(sdb) cont
hello, world!
** hit a breakpoint at 0x4000cb
      4000cb: bb 00 00 00 00                  mov       ebx, 0
      4000d0: cd 80                           int       0x80
      4000d2: c3                              ret       
** the address is out of the range of the text section.
(sdb) timetravel
** go back to the anchor point
      4000b0: b8 04 00 00 00                  mov       eax, 4
      4000b5: bb 01 00 00 00                  mov       ebx, 1
      4000ba: b9 d4 00 60 00                  mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                  mov       edx, 0xe
      4000c4: cd 80                           int       0x80
(sdb) cont
hello, world!
** hit a breakpoint at 0x4000cb
      4000cb: bb 00 00 00 00                  mov       ebx, 0
      4000d0: cd 80                           int       0x80
      4000d2: c3                              ret       
** the address is out of the range of the text section.
```
### GET
Command : `get <register>`  
When a user use `get <register>` to get a value of register. The debugger will print a value about the register.  

#### implement detail
When getting a register. 
1. Use `ptrace(GETREG)` to see information of all register.  
2. Return the value of register. 

```shell=
** program './sdb' loaded. entry point 0x401000  
      401000: f3 0f 1e fa                       endbr64    
      401004: 55                                push      rbp 
      401005: 48 89 e5                          mov       rbp, rsp
      401008: ba 0e 00 00 00                    mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00              lea       rax, [rip + 0xfec]
(sdb) get rax
rax : 0
(sdb) 
```
 
### SET 
Command : `set <register>  <value>(hex)`   
When a user use `set <register>  <value>(hex)` to set a value of register. The debugger will print a value about the register after setting.  
 
#### implement detail
When setting a register. 
1. Use `ptrace(SETREG)` to set register.  
2. Return the value of register after setting. 

```shell= 
** program './sdb' loaded. entry point 0x401000 
      401000: f3 0f 1e fa                       endbr64   
      401004: 55                                push      rbp
      401005: 48 89 e5                          mov       rbp, rsp
      401008: ba 0e 00 00 00                    mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00              lea       rax, [rip + 0xfec]
(sdb) set rax 0x40
rax : 40
(sdb) 
```

### VMMAP
Command : `vmmap`  
When a user use `vmmap` to see the maps of the target process. The debugger will desplay the maps of target process.  

#### implement detail 
Load maps of process and store when debugger starting.  
When the user call the `vmmap` function 
2. Display the all maps information of target process. 

```shell=
** program './sdb' loaded. entry point 0x401000 
      401000: f3 0f 1e fa                       endbr64   
      401004: 55                                push      rbp
      401005: 48 89 e5                          mov       rbp, rsp
      401008: ba 0e 00 00 00                    mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00              lea       rax, [rip + 0xfec]
(sdb) vmmap
00400000-00401000 r--p 00000000 fd:00 32001262                           /home/dave/hw2/hello
00401000-00402000 r-xp 00001000 fd:00 32001262                           /home/dave/hw2/hello
00402000-00403000 r--p 00002000 fd:00 32001262                           /home/dave/hw2/hello
7fffb061e000-7fffb063f000 rwxp 00000000 00:00 0                          [stack]
7fffb0728000-7fffb072c000 r--p 00000000 00:00 0                          [vvar]
7fffb072c000-7fffb072e000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
(sdb) 
```