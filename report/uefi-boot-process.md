# UEFI 启动流程

https://wiki.archlinux.org/index.php/Unified_Extensible_Firmware_Interface

## UEFI
UEFI(Unified Extensible Firmware Interface)是一种新型固件。它引入一种启动操作系统的
新方式。该方式有别于BIOS系统所使用的“MBR启动代码”方法。
>如果特殊说明，本文中“固件”即为“UEFI固件”

### UEFI引导过程
  1. 系统开机——上电自检（Power On Self Test 或 POST）。
  2. UEFI固件被加载。固件初始化启动时必须的硬件。
  3. 固件读取其引导管理器数据以确定从何处（比如，从哪个硬盘和分区）加载哪个UEFI应用。
  4. 固件按照引导管理器中的启动项目，加载UEFI应用。
  5. 已启动的 UEFI 应用还可以启动其他应用（比如UEFI shell 或 类似rEFInd的启动管理器）、
内核及initramfs（对应于GRUB之类boot loader的情况），这取决于 UEFI 应用的配置。

    > 注意： 在有些 UEFI 系统中，(如果在 UEFI 启动菜单没有定制条目的话，又）想要启动时加载UEFI应用，加载UEFI应用的方法)唯一可行的方法是把它放在这个固定位置：<EFI SYSTEM PARTITION>/EFI/boot/bootx64.efi （对于 64 位的 x86 系统）

#### 启动

EFI 载入默认的boot loader(通常为 EFI/BOOT/bootx64.efi)或者一个文件名存放在固件闪存的 boot loader 中。


#### UEFI 的多重引导

因为每个操作系统或者提供者都可以维护自己的 EFI 系统分区中的文件，同时不影响其他系统，所以UEFI的多重启动只是简单的运行不同的UEFI程序，对应于特定操作系统的引导程序。这避免了依赖chainloading机制（通过一个引导程序加载另一个引导程序，来切换操作系统）。 

### Linux 内核中有关 UEFI 的配置选项
UEFI 系统所要求的 Linux 内核配置选项设置如下:

```
CONFIG_RELOCATABLE=y
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_FB_EFI=y
CONFIG_FRAMEBUFFER_CONSOLE=y
```
UEFI运行时变量支持 (efivarfs 文件系统 - /sys/firmware/efi/efivars). 该选项十分重要，因为它是使用如 /usr/bin/efibootmgr 的工具来操作UEFI运行时变量所必须的。下面的选项已添加进了版本3.10及以上的内核中。

```
CONFIG_EFIVAR_FS=y
```

GUID 分区表 GPT 配置选项 - UEFI 支持的强制需求

```
CONFIG_EFI_PARTITION=y
```

### UEFI变量
UEFI定义了变量，操作系统通过它们可以与固件交互。UEFI引导变量只是在早期系统启动时由引
导加载程序和操作系统使用。UEFI运行时允许操作系统来管理固件的某些设置或（如UEFI引导管
理器）UEFI Secure Boot协议的密钥。

#### Linux内核中的UEFI变量支持
efivarfs接口（CONFIG_EFIVAR_FS） 由位于 /sys/firmware/efi/efivars 的 efivarfs 内核模块挂载使用，
不限制变量数据大小，支持UEFI Secure Boot变量并被上游推荐使用。

#### UEFI 变量正常工作的需求

1. EFI 运行时服务支持应出现在内核中 (CONFIG_EFI=y, 运行 zgrep CONFIG_EFI /proc/config.gz 来核对是否共存 ).
2. 内核处理器的位数/架构应该与EFI处理器的位数/架构相符。
3. 内核应以 EFI 模式(通过 EFISTUB 或 EFI 引导器，而不是 BIOS/CSM 或者同为 BIOS/CSM 的"bootcamp")启动。
4. EFI 运行时服务在内核命令行中不应被禁用，即不应使用内核参数 noefi.
5. efivarfs 文件系统应被挂载在 /sys/firmware/efi/efivars, 否则参考下文 #挂载 efivarfs 部分。
6. efivar 应无错列出 (选项 -l) EFI 变量。参见输出内容 #Sample_List_of_UEFI_Variables.

#### 用户空间工具

只有少量工具能够访问/修改 UEFI 变量，即

   1. efivar - 操作 UEFI 变量的库和工具 (被 efibootmgr 用到)
   2. efibootmgr - 操作 UEFI 固件启动管理器设置的工具
   3. uefivars - 转储 UEFI 变量和 PCI 相关信息 (内部使用 efibootmgr 源码) 
   4. efitools - 创建与设置自己的 UEFI Secure Boot 证书，密钥和签名过的程序的工具 (需要 efivarfs)
   5. Ubuntu的固件测试套件

### EFI系统分区
EFI系统分区（也称ESP或者EFISYS）是一个FAT32格式的物理分区（在硬盘主分区表上，而不是
LVM或者软件RAID等等），从这里UEFI固件启动UEFI引导器和应用程序。

它与操作系统无关而是作为EFI固件要启动的引导器和应用程序的存储空间，是UEFI启动所必须。
它的分区类型应该是EFI系统分区。推荐 ESP 大小为 512 MiB 尽管大一点小一点都没问题 (见下面的注意)。

>注意:
 - 推荐使用 GPT 和 UEFI 搭配因为有的 UEFI 固件不支持 UEFI-MBR 启动。
 - 在 GNU Parted 中， boot 参数 (不要与 legacy_boot 参数搞混了) 在 MBR 和 GPT 盘上作用不同。在 MBR 硬盘上，它标识分区为活动分区。在 GPT 硬盘上，它把分区编码改为 EFI System Partition 类型。 Parted 没有在 MBR 上标识 ESP 的参数 (尽管可以通过 fdisk 完成)。
 - Microsoft 文献注解了 ESP 大小: 对高级格式化 (Advanced Format) 4K 本地驱动器 (每扇区4KB) 来说，由于 FAT32 文件格式的限制，最小为 260 MB。 FAT32 的最小分区大小可由扇区大小 (4KB) x 65527 = 算出 256 MB。高级格式化 512e 驱动器不受此限制影响，因为其虚拟扇区是 512B. 512 bytes x 65527 = 32 MB, 这比 100 MB 最小限制还要小
 - 为防止 EFISTUB, 内核以及 initramfs 文件应储存在 EFI 系统分区。精简起见，当以 EFISTUB 启动时你可以把 ESP 当做 /boot 分区而不是单独分一个 /boot 分区。 

### UEFI Shell

UEFI Shell 是固件的终端，可用于启动包括引导器的 UEFI 程序。除此之外， Shell也可用于采集固件和系统的各种信息，例如内存映射 (memmap), 修改启动管理器变量 (bcfg), 运行分区程序 (diskpart), 加载 UEFI 驱动，编辑文本文件 (edit), 十六进制编辑等等。 

