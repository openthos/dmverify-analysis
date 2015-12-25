# EFI 启动流程

**入门**

> 还需要继续整理

固件知道怎么读取分区表，FAT文件格式
EFI文件分区 一个真实的文件卷
包含 bootloader程序，她通常是一个EFI可执行程序 由EFI启动管理 载入和运行。

EFI可执行程序是一个独立的程序，机器固件服务
他们可以是操作系统启动载入 或者预启动 maintenance/诊断程序

EFI启动管理器

EFI启动管理器的细节取决于固件的实现，但所有启动管理器配置成 使用well-known EFI变量，他们公开定义和发布 保持固件配置数据。
启动管理器被要求/需要 检查EFI变量 behave accordingly。
主要变量是 BootOrder EFI变量。他们有两个主要使用情况

* 一个系统 没有BootOrder EFI变量 
 仍然没有可启动的操作系统的系统。 启动管理器 fall back to 回滚到 一个过程，调用 查找boot loader 文件在标准位置，软盘，光盘或其它磁盘启动载入
将开始一个操作系统安装()

特别的是，在这种情况下，EFI启动管理器被要求枚举所有可移动的DASD和固定的DASD。对于可移动DASD，磁盘被当作包含一个简单卷。对于固定DASD，磁盘查找EFI文件系统分区，卷被使用。在所有情况中，EFI启动管理器查找一个EFI可执行程序去执行 存放在指定卷， 叫做 \EFI\BOOT\BOOTtype.EFI（type通常是IA32,IA64,一些其他字符串，根据CPU的体系结构）。这是一个默认的操作系统启动载入器。

* 一个系统带有 BootOrder EFI变量是一个系统有一个或多个已经安装且可启动的操作系统。
and a simpler scenario ensues。这个变量包含一系列EFI启动选项。一个启动选项是 另一个EFI变量的应用。 有一个标准命名格式，包含一个EFI可执行程序的设备和路径名 载入和运行，及一组变量传递给这个程序。启动管理器显示 这些启动选项（“display name”的一部分 启动管理器目录） 的一个列表，用户选择一个选项去启动，启动管理器 载入并调用被选中的启动载入程序，传递给他各种EFI设备路径，指定配置

许多情况，EFI启动进程非常类似ARC启动进程：有一个启动管理器在固件中，使用一个数据库包含（comprising）一组固件变量（）,它提供一个选项列
这提出了一个用户选择的选项列表，这将导致一个装载程序运行和一些选项以传递给它。

不同的都在细节方面。EFI设备路径 比ARC路径更具有表现力，
EFI启动管理器有一个选项 去 启动一个命令行接口，EFI Shell。
有一个定义良好的固件接口 ，它们有一个定义明确的扩展机制 为添加东西 比如额外的文件型驱动 来允许启动时访问磁盘卷 以 FAT以外的 文件系统格式 格式化。

Boot Loader
通常，所有的操作系统bootloader存放在EFI系统分区,在一个供应商特定子目录 \EFI\ 目录中。

### Windows NT Version 5.x
64位版本，EFI boot loader \EFI\Microsoft\WINNT50\IA64LDR.EFI（有时 \EFI\Microsoft\WINNT50C\IA64LDR.EFI）,包含(comprises) NTLDR, Windows NT boot loader ...

### Windows NT versions 6.x
对于Windows Nt 6,EFI boot loader \EFI\Microsoft\Boot\Bootmgfw.efi，它是Windows启动管理器-另一个启动管理器，他

### Linux
对于64为版本，EFIboot loader \EFI\ReaHat\elilo.efi 或者 \EFI\SuSE\elilo.efi
ELILO,就像Microsoft启动管理器，也包含一个二级启动选项








