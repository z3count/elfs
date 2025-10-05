# ELFS — A FUSE Filesystem for ELF Binaries exploration 🧩🐧

**ELFS** lets you mount an ELF object (executable or shared library) as a filesystem using **FUSE**.  
It’s primarily an educational tool: browse headers, sections, symbols, and linked libraries as if they were files and directories.

---

## ✨ Features

- Mount any ELF and explore its **header**, **sections**, **symbols**, and **dependencies**.
- Inspect disassembly (`*.asm`) and raw bytes (`*.bin`) of functions and sections.
- See runtime library resolution for binaries (via `ldd(1)`).
- (Experimental) Attach to a **running process** and explore its mapped objects.

---

## 📦 Requirements

You’ll need the following tools on your system:

- `ldd(1)`
- `objdump(1)`
- A working **FUSE** setup

---

## 🚀 Installation

Clone the repository and build:

```bash
git clone https://github.com/z3count/elfs.git
cd elfs
```
### On Linux:

```bash
make
```

### On BSD:

```bash
make -f Makefile.BSD
```

### Install (requires root):

```bash
sudo make install
```

## 🔧 Usage
Mount an ELF image into a directory (e.g., `/tmp/elf`).
In this example we inspect `fdup(1)`; replace it with any ELF on your system.

```bash
elfs "$(which fdup)" /tmp/elf
```

List the top-level layout:

```bash
ls -l /tmp/elf/
# total 0
# drw-r--r-- 1 root root 0 Jan  1  1970 header
# drw-r--r-- 1 root root 0 Jan  1  1970 libs
# drw-r--r-- 1 root root 0 Jan  1  1970 sections
```

### 📜 Header

The header/info file mirrors what you’d get from `readelf -h`:

```bash
cat /tmp/elf/header/info
# Ident:                             7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
# Version:                           1
# Class:                             64
# Type:                              EXEC (Executable file)
# ELF Header size:                   64 bytes
# Entry point:                       0x400f50
# Program Header offset:             64 bytes
# Program Header entry size:         56 bytes
# Number of Program Header entries:  9
# Section Header offset:             84552 bytes
# Section Header entry size:         64 bytes
# Number of Section Header entries:  38
# SH string table index:             35
```

### 📚 Libraries
Browse dynamically linked libraries and their resolved paths:

```bash
ls -l /tmp/elf/libs
# total 0
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libc.so.6 -> /lib/x86_64-linux-gnu/libc.so.6
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 linux-vdso.so.1 ->
```

### 🧩 Sections
Each ELF section appears as a directory or file under `sections/`:

```bash
ls -l /tmp/elf/sections/
# total 0
# drw------- 1 root root 0 1970-01-01 01:00 bss
# d--------- 1 root root 0 1970-01-01 01:00 comment
# drw------- 1 root root 0 1970-01-01 01:00 ctors
# drw------- 1 root root 0 1970-01-01 01:00 data
# d--------- 1 root root 0 1970-01-01 01:00 debug_abbrev
# d--------- 1 root root 0 1970-01-01 01:00 debug_aranges
# d--------- 1 root root 0 1970-01-01 01:00 debug_info
# d--------- 1 root root 0 1970-01-01 01:00 debug_line
# d--------- 1 root root 0 1970-01-01 01:00 debug_loc
# d--------- 1 root root 0 1970-01-01 01:00 debug_macinfo
# d--------- 1 root root 0 1970-01-01 01:00 debug_pubnames
# d--------- 1 root root 0 1970-01-01 01:00 debug_pubtypes
# d--------- 1 root root 0 1970-01-01 01:00 debug_ranges
# d--------- 1 root root 0 1970-01-01 01:00 debug_str
# drw------- 1 root root 0 1970-01-01 01:00 dtors
# drw------- 1 root root 0 1970-01-01 01:00 dynamic
# dr-------- 1 root root 0 1970-01-01 01:00 dynstr
# dr-------- 1 root root 0 1970-01-01 01:00 dynsym
# dr-------- 1 root root 0 1970-01-01 01:00 eh_frame
# dr-------- 1 root root 0 1970-01-01 01:00 eh_frame_hdr
# dr-x------ 1 root root 0 1970-01-01 01:00 fini
# dr-------- 1 root root 0 1970-01-01 01:00 gnu.hash
# dr-------- 1 root root 0 1970-01-01 01:00 gnu.version
# dr-------- 1 root root 0 1970-01-01 01:00 gnu.version_r
# drw------- 1 root root 0 1970-01-01 01:00 got
# drw------- 1 root root 0 1970-01-01 01:00 got.plt
# dr-x------ 1 root root 0 1970-01-01 01:00 init
# dr-------- 1 root root 0 1970-01-01 01:00 interp
# drw------- 1 root root 0 1970-01-01 01:00 jcr
# d--------- 1 root root 0 1970-01-01 01:00 noname.0x7f14e3a863c0
# dr-------- 1 root root 0 1970-01-01 01:00 note.ABI-tag
# dr-------- 1 root root 0 1970-01-01 01:00 note.gnu.build-id
# dr-x------ 1 root root 0 1970-01-01 01:00 plt
# dr-------- 1 root root 0 1970-01-01 01:00 rela.dyn
# dr-------- 1 root root 0 1970-01-01 01:00 rela.plt
# dr-------- 1 root root 0 1970-01-01 01:00 rodata
# d--------- 1 root root 0 1970-01-01 01:00 shstrtab
# d--------- 1 root root 0 1970-01-01 01:00 strtab
# d--------- 1 root root 0 1970-01-01 01:00 symtab
# dr-x------ 1 root root 0 1970-01-01 01:00 text
```

Section permissions map to ELF Section Header flags:

- SHF_WRITE     → w
- SHF_ALLOC     → r
- SHF_EXECINSTR → x

### 🧠 Read the whole .text in assembly

```bash
cat /tmp/elf/sections/text/code.asm
```

### 🔎 Inspect a specific symbol

```bash
ls -l /tmp/elf/sections/symtab/dup_cmp_gid/
# total 0
# -rw-r--r-- 1 root root 914 Jan  1  1970 code.asm
# -rw-r--r-- 1 root root  44 Jan  1  1970 code.bin
# -rw-r--r-- 1 root root  72 Jan  1  1970 info

cat /tmp/elf/sections/symtab/dup_cmp_gid/info
# value: 0x401af0
# size: 44
# type: STT_FUNC
# bind: STB_LOCAL
# name: GLIBC_2.3.4
```

View bytes and disassembly:

```bash
od -t x1 /tmp/elf/sections/symtab/dup_cmp_gid/code.bin

cat /tmp/elf/sections/symtab/dup_cmp_gid/code.asm
# /home/user/code/fdup/fdup:     file format elf64-x86-64
#
# Disassembly of section .text:
#
# 0000000000401af0 <dup_cmp_gid>:
#   401af0: 55                      push   %rbp
#   401af1: 48 89 e5                mov    %rsp,%rbp
#   401af4: 48 89 7d f8             mov    %rdi,-0x8(%rbp)
#   401af8: 48 89 75 f0             mov    %rsi,-0x10(%rbp)
#   401afc: 48 8b 45 f8             mov    -0x8(%rbp),%rax
#   401b00: 8b 50 20                mov    0x20(%rax),%edx
#   401b03: 48 8b 45 f0             mov    -0x10(%rbp),%rax
#   401b07: 8b 40 20                mov    0x20(%rax),%eax
#   401b0a: 39 c2                   cmp    %eax,%edx
#   401b0c: 75 07                   jne    401b15 <dup_cmp_gid+0x25>
#   401b0e: b8 00 00 00 00          mov    $0x0,%eax
#   401b13: eb 05                   jmp    401b1a <dup_cmp_gid+0x2a>
#   401b15: b8 ff ff ff ff          mov    $0xffffffff,%eax
#   401b1a: 5d                      pop    %rbp
#   401b1b: c3                      retq
```

### ✅ Cross-check with toolchain
The symbol size is 44 bytes (`0x2c`), so it ends at `0x401af0 + 0x2c = 0x401b1c`:

```bash
readelf -s /usr/local/bin/fdup | grep dup_cmp_gid
# 60: 0000000000401af0    44 FUNC    LOCAL  DEFAULT   13 dup_cmp_gid
objdump -D --start-address=0x401af0 --stop-address=0x401b1c /usr/local/bin/fdup
```

### 🧪 Experimental: attach to a running process
⚠️ This feature is experimental; unexpected behavior may occur.

```bash
sudo elfs -p "$(pidof xclock)" /tmp/elf
sudo ls -l /tmp/elf/libs
# total 0
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libc.so.6 -> /lib/x86_64-linux-gnu/libc.so.6
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libdl.so.2 -> /lib/x86_64-linux-gnu/libdl.so.2
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libexpat.so.1 -> /lib/x86_64-linux-gnu/libexpat.so.1
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libfontconfig.so.1 -> /usr/lib/x86_64-linux-gnu/libfontconfig.so.1
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libfreetype.so.6 -> /usr/lib/x86_64-linux-gnu/libfreetype.so.6
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libICE.so.6 -> /usr/lib/x86_64-linux-gnu/libICE.so.6
# lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libm.so.6 -> /lib/x86_64-linux-gnu/libm.so.6
# [...]
```

### 🆘 Help
```bash
elfs -h
```

### 🧹 Uninstall
From the source directory (requires root):

```bash
sudo make uninstall
```

### 🐞 Issues
Found a bug? Have an idea? Please open an issue:

https://github.com/z3count/elfs/issues

### 💡 Notes
Timestamps like Jan 1 1970 are placeholders from the virtual filesystem; they’re expected.

You usually don’t need to be root to mount with FUSE (depends on your system policy), but installation typically requires root.

