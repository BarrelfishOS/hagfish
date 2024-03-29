# Hagfish

This is the Barrelfish/ARMv8 UEFI loader prototype: Hagfish (it's a basal
chordate i.e. something like the ancestor of all fishes).

## What Is Hagfish?

Hagfish is a second-stage bootloader for Barrelfish on UEFI platforms, most
importantly the ARMv8 server platform.

Hagfish is loaded as a UEFI application, and uses the large set of supplied
services to do as much of the one-time (boot core) setup that the CPU driver
needs as is reasonably possible.  More specifically, Hagfish:
 * Is loaded over BOOTP/PXE.
 * Reuses the PXE environment to load a `menu.lst`-style configuration.
 * Loads the kernel image and the initial applications, according to configuration.
 * Allocates and builds the CPU driver's initial (direct-mapped) page table.
 * Activates the initial page table, and allocates a stack.

## Why Another Bootloader?

The ARMv8 machines that we're porting to are different both to existing ARM
boards, and to x86.  They have a full pre-boot environment, unlike most
embedded boards, but it's not a PC-style BIOS.  The ARM Server Base Boot
Requirements [[1]](#ref1) specify UEFI.  Moreover, there is no mainline support from
GNU GRUB for the ARMv8 architecture, so no matter what, we need some amount of
fresh code.

Given that we had to write at least a shim loader, and keeping in mind that
UEFI is multi-platform (and becoming more and more common in the x86 world),
we're taking the opportunity to simplify the initial boot process within the
CPU driver by moving the once-only initialisation into the bootloader.  In
particular, while running under UEFI boot services, we have memory allocation
available for free, e.g. for the initial page tables.  By moving ELF loading
and relocation code into the bootloader, we can eliminate the need to relocate
running code, and can cut down (hopefully eliminate) special-case code for
booting the initial core.

## Technical Details

### Assumptions and Requirements

Hagfish is (initially at least) intended to support development work on
AArch64 server-style hardware and, as such, makes the following assumptions:

 * 64-bit architecture, using ELF binaries.  Porting to 32-bit architectures
   wouldn't be hard, though.
 * PXE/BOOTP/TFTP available for booting.  Hagfish expects to load its
   configuration, and any binaries needed, using the same PXE context with
   which it was booted.  Changing this to boot from a local device (e.g. HDD)
   wouldn't be hard, as the LoadFile interface abstracts from the hardware.

### Boot Process

In detail, Hagfish currently boots like this:

 1. Hagfish.efi is loaded over PXE by EFI, and is executed at a
    runtime-allocated address, with translation (MMU) and caching enabled.
 2. Hagfish queries EFI for the PXE protocol instance used to load it, and
    squirrels away the current network configuration.
 3. Hagfish loads the file `hagfish.A.B.C.D.cfg` from the TFTP server root
    (where A.B.C.D is the IP address on the interface that ran PXE).
 4. Hagfish parses its configuration, which is essentially a GRUB `menu.lst`,
    and loads the kernel image and any additional modules specified therein.
    All ELF images are loaded into page-aligned regions of type
    `EfiBarrelfishELFData`.
 5. Hagfish queries EFI for the system memory map, then allocates and
    initialises the initial page tables for the CPU driver (1-1 mapping of all
    occupied physical addresses).  The frames holding these tables are marked
    with the EFI memory type, `EfiBarrelfishBootPagetable`, allocated from the
    OS-specific range (`0x80000000-0x8fffffff`).  All memory allocated by
    Hagfish on behalf of the CPU driver is page-aligned, and tagged with an
    OS-specific type, to allow EFI and Hagfish regions to be safely reclaimed.
 6. Hagfish builds a Multiboot 2 information structure, containing as much
    information as it can get from EFI, including:
    * ACPI 1.0 and 2.0 tables.
    * The EFI memory map (including Hagfish's custom-tagged regions).
    * Network configuration (the saved DHCP ack packet).
    * The kernel command line.
    * All loaded modules.
    * The kernel's ELF section headers.
 7. Hagfish allocates a page-aligned kernel stack (type
    `EfiBarrelfishCPUDriverStack`), of the size specified in the configuration.
 8. Hagfish terminates EFI boot services (calls ExitBootServices), activates
    the CPU driver page table, switches to the kernel stack, and jumps into
    the relocated CPU driver image.

### Post-boot state

When the CPU driver on the boot core begins executing, the following
statements hold:
 * The MMU is configured with a 1-1 translation of all RAM and I/O regions.
 * The CPU driver's code and data are both fully relocated into one or more
   distinct 4kiB-aligned regions.
 * The stack pointer is at the top of a distinct 4kiB-aligned region of at
   least the configured size.
 * The first argument register holds the Multiboot 2 magic value.
 * The second holds a pointer to a Multiboot 2 information structure, in a
   distinct 4kiB-aligned region.
 * The console device is configured.
 * Only one core is enabled.
 * The Multiboot structure contains at least:
  * The final EFI memory map, with all areas allocated by Hagfish to hold data
    passed to the CPU driver marked with OS-specific types, all of which refer
    to non-overlapping 4kiB-aligned regions:
       EfiBarrelfishCPUDriver ::
           The currently-executing CPU driver's text and data segments (these
           may be allocated together or separately).
       EfiBarrelfishCPUDriverStack ::
           The CPU driver's stack
       EfiBarrelfishMultibootData ::
           The Multiboot structure.
       EfiBarrelfishELFData ::
           The unrelocated ELF image for a boot-time module (including that
           for the CPU driver itself), as loaded over TFTP.
       EfiBarrelfishBootPageTable ::
           The currently-active page tables.
  * The CPU driver (kernel) command line.
  * A copy of the last DHCP ack packet.
  * A copy of the section headers from the CPU driver's ELF image.
  * Module descriptions for the CPU driver and all other boot modules.
 * If EFI provided an ACPI root table, the Multiboot structure contains a
   pointer to it.

## Using Hagfish

### Downloading

The current Hagfish development tree is available at `https://github.com/BarrelfishOS/hagfish`.

Clone it with:
```
$ git clone https://github.com/BarrelfishOS/hagfish.git
```

### Building

Hagfish is built using the [UEFI embedded development kit (EDKII)](https://github.com/tianocore/edk2)
(tested on `edk2-stable201908` tag).
Clone it to somewhere outside this repository and compile the build tools:
```
git clone -b edk2-stable201908 https://github.com/tianocore/edk2.git ${PATH_TO_EDK2}
make -C ${PATH_TO_EDK2}/BaseTools/
```

Hagfish also depends on the C standard library.
Clone an UEFI port of it to somewhere outside this repository:
```
git clone https://github.com/tianocore/edk2-libc.git ${PATH_TO_LIBC}
```

To compile Hagfish you'll need an AArch64-compatible cross compiler, on Ubuntu 18.04 you can install
the `gcc-aarch64-linux-gnu` package.

Setup the build environment by sourcing `setup_env.sh`:
```
source ./setup_env.sh ${PATH_TO_EDK} ${PATH_TO_LIBC} ${PATH_TO_HAGFISH}
```
The arguments default to the following:
```
PATH_TO_HAGFISH=$(pwd)
PATH_TO_EDK=${PATH_TO_HAGFISH}/../edk2
PATH_TO_LIBC=${PATH_TO_EDK}/../edk2-libc
```

Then build Hagfish:
```
build -a AARCH64 -t GCC5 -p Hagfish/Hagfish.dsc -m Hagfish/Application/Hagfish/Hagfish.inf -b DEBUG
```
The image will be at `${PATH_TO_EDK}/Build/Hagfish/DEBUG_GCC5/AARCH64/Hagfish.efi`.

### Booting

Once you've got a copy of `Hagfish.efi`, copy it into the TFTP server's
subtree and configure your DHCP server to pass its relative path to the
machine you wish to boot.  The Mustang boards will automatically attempt a PXE
boot, as should most EFI machines, where no local boot device is configured.

### Debugging

What you need:
 * GDB for AARCH64. If not in your OS's repository, go to [[2]](#ref2)
 * Symbol file: `edk2/Build/Hagfish/DEBUG_GCC5/AARCH64/Hagfish/Application/Hagfish/Hagfish/DEBUG/Hagfish.dll`

Steps:

 * Set `WAIT_FOR_GDB = 1` in Hagfish.dsc
 * rebuild Hagfish
 * extract the debug symbols:
   ```
   $ aarch64-linux-gnu-objcopy --only-keep-debug \
     edk2/Build/Hagfish/DEBUG_GCC5/AARCH64/Hagfish/Application/Hagfish/Hagfish/DEBUG/Hagfish.dll \
     Hagfish.sym
    ```
 * run GBD and attach to host, e.g. QEMU
 * start the execution until you see:
   ```
   Hagfish loaded at 78449000, size 310304B, by handle 7B0CCB98
   ```
 * 
   ```
   (gdb) info files
   Entry point: 0x0
   0x0000000000000000 - 0x000000000003f924 is .text
   0x000000000003f928 - 0x0000000000046026 is .rodata
   0x0000000000056028 - 0x0000000000056e3a is .data
   0x0000000000056e40 - 0x000000000005ad90 is .bss
   0x0000000004ad0968 - 0x0000000004b1028c is .text in /local/code/hagfish.sym
   0x000000000003f928 - 0x0000000000046026 is .rodata in /local/code/hagfish.sym
   0x0000000000056028 - 0x0000000000056e3a is .data in /local/code/hagfish.sym
   0x0000000000056e40 - 0x000000000005ad90 is .bss in /local/code/hagfish.sym
   ```
 * Add the symbols at the right address: Use the load address and calculate the new location of the data section (`0x56e3a + 0x78449000`)
   ```
   (gdb) add-symbol-file Hagfish.sym 0x78449000 -s .data 0x784afe3a
   (gdb) set variable wait = 0
   (gdb) continue
   ```

### Configuration

Hagfish configures itself by loading a file whose path is generated from its
assigned IP address.  Thus if your development machine receives the address
`192.168.1.100`, Hagfish will load the file `hagfish.192.168.1.100.cfg` from
the same TFTP server used to load it.  The format is intended to be as close
as practical to that of an old-style GRUB menu.lst file.  The following
example loads `/armv8/sbin/cpu_apm88xxxx` as the CPU driver, with arguments
`loglevel=4`, and an 8192B (2-page) stack.

#### Configuration example
```
#
# This script is used to describe the commands to start at
# boot-time and the arguments they should receive.
#

kernel /armv8/sbin/cpu_apm88xxxx loglevel=4
stack 8192
module /armv8/sbin/cpu_apm88xxxx
module /armv8/sbin/init

# Domains spawned by init
module /armv8/sbin/mem_serv
module /armv8/sbin/monitor

# Special boot time domains spawned by monitor
module /armv8/sbin/chips boot
module /armv8/sbin/ramfsd boot
module /armv8/sbin/skb boot
module /armv8/sbin/kaluga boot
module /armv8/sbin/spawnd boot bootarm=0
module /armv8/sbin/startd boot

# General user domains
module /armv8/sbin/serial auto portbase=2
module /armv8/sbin/fish nospawn
module /armv8/sbin/angler serial0.terminal xterm

module /armv8/sbin/memtest

module /armv8/sbin/corectrl auto
module /armv8/sbin/usb_manager auto
module /armv8/sbin/usb_keyboard auto
module /armv8/sbin/sdma auto
```

## Copyright

Most of the code in Hagfish is owned by ETH Zuerich, and released under the
license terms given in the LICENSE file.  If any files are under a different
license (or from a different owner), they are marked as such in their header.

## References
<a name="ref1"></a>[1] http://infocenter.arm.com/help/topic/com.arm.doc.den0044a/Server_Base_Boot_Requirements.pdf

<a name="ref2"></a>[2] https://www.linaro.org
