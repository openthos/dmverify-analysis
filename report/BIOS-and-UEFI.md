# BIOS 与 UEFI

## BIOS
所谓BIOS或Basic Input-Output System, 就是开机时第一个被执行的程序，又名固件。一般来说它被储存在主板上的一块闪存，与硬盘彼此独立。

BIOS被启动后，它接着会执行第一个硬盘上的前440字节代码，即Master Boot Record, 由于代码的储存空间实在太小了，所以实际代码常常是某个bootloader，像 GRUB (简体中文), Syslinux (简体中文) 和 LILO 之类的。最后启动引导器又通过「链式引导」，或是直接加载内核，以加载一个操作系统

## UEFI
 不光能读取分区表，还能自动支持文件系统。所以它不像 BIOS, 已经没有只能执行 440 字节代码即 MBR 的限制了，它完全用不到 MBR.
UEFI 主流都支持 MBR 和 GPT 分区表。Apple-Intel Macs 上的 EFI 还支持 Apple 专用分区表。绝大部分 UEFI 固件支持软盘上的 FAT12, 硬盘上的 FAT16, FAT32 文件系统，以及 CD/DVDs 的 IS09660 和 UDF. Intel Macs 的 EFI 还额外支持 HFS/HFS+ 文件系统。
不管第一块上有没有 MBR, UEFI 都不会执行它。相反，它依赖分区表上的一个特殊分区，叫 EFI 系统分区，里面有 UEFI 所要用到的一些文件。计算机供应商可以在 <EFI系统分区>/EFI/<VENDOR NAME>/ 文件夹里放官方指定的文件，还能用固件或它的 shell, 即 UEFI shell, 来启动引导程序。EFI 系统分区一般被格式化成 FAT32, 或比较非主流的 FAT16.

UEFI 下每一个程序，无论它是某个 OS 引导器还是某个内存测试或数据恢复的工具，都要兼容于 EFI 固件位数或体系结构。目前主流的 UEFI 固件，包括近期的 Apple Macs, 都采用了 x86_64 EFI 固件。目前还在用 IA32 即 32 位的 EFI 的已知设备只有于 2008 年前生产的 Apple Macs, 一些 Intel Cloverfield 超级本和采用 EFI 1.10 固件的 Intel 服务器主板。 

不像 x86_64 Linux 和 Windows 操作系统，x86_64 EFI 不能兼容 32 位 EFI 程序。所以 UEFI 应用程序必须依固件处理器位数／体系结构编译而成。 



