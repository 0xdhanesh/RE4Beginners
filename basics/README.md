
# File 
## MSB - from file output
- MSB stands for "Most Significant Byte" directly refers to "Big-Endian"
- Big Endian are used on older architectures like **PowerPc** (_older Macs_), MIPS and SPARC
- Also the standard byte order for networking Protocols (often called as "Network byte order")
- D/B Little Endian and Big Endian is how the data are stored 
	- **Example:** The 32-bit number `0x12345678`
	- **Big-Endian (MSB):** Stored in memory as `12 34 56 78`
	- **Little-Endian (LSB):** Stored in memory as `78 56 34 12`
- Crucial to know the endianess, as exploit developers are required to craft the memory addresses to craft it into the exploits which inturn will be loaded by the architecture

## Static Linked ELF binaries
- During compilation, a static linker copies all the necessary code from the libraries a program uses directly into the final executable file. 
- The resulting binary is a single, self-contained file with no external library dependencies.
- Kind of like a `portable binary`
- Real World example include
	- Embedded Systems / IoT, as the size of the shared libraries could be large and only minimal space is available in the device
	- Softwares that needed to avoid dependency issues as these the softwares could be Mission-Critical software
	- Portable Command-Line tools; go language binaries are often statically linked

## Attacks on Dynamic Linkers
- `LD_PRELOAD` Hijacking
- Link Map Corruption

## Static Linkers / Dynamic Linkes

![[Compilation Process.png]]

- The static linker are fundamental part of any compiler tool chain
- It takes all the compiled objects (`.o`) files and link them together to create a single cohesive executable or library

## Stripped Binary and Symbol Table
### Method 1 - Breakpoint at `__libc_start_main`: 
- Find main: The program's entry point (`_start`) calls a libc function (`__libc_start_main`) which in turn calls main. 
- By setting a breakpoint on `__libc_start_main` in a debugger, you can find the address of main from its arguments.
### Method 2 - Identifying library calls:
- Calls to shared lib functions are not stripped
- These are resolved via Procedure Linkage Table `PLT`
- By identifying what library functions are being called, you can infer the purpose of the code around the call.
### Method 3 - Analyzing Strings:
- By analyzing the strings in the `rodata` sections, could provide a huge hints about the function and how it is used
### Method 4 - Dynamic Analysis
- By using debuggers to run the program like `GDB`
- Trace its execution with different inputs to see what code paths are taken and how data in memory changes.
### Method 5 - Cross-Referencing
- Use a disassembler (like Ghidra or IDA Pro) to see where a function is called from and what other functions it calls. 
- This helps build a call graph and understand relationships between code blocks.