#关于rEFInd及安装

rEFInd 是一个 UEFI 启动管理器(boot manager)。它被设计为平台无关，可启动多个操作系统。 

## 安装及细节

### Linux 中安装 rEFInd
从官方软件源安装refind-efi后，运行

    refind-install
此操作会检测您的内核和 ESP 分区，复制需要的文件，创建默认配置文件并将 rEFInd 设置为默认的 UEFI 启动项

手动安装可以帮助我们了解 rEFInd 如何工作，以64为的Linux为例

1. 在 ESP 中创建一个目录来存放 rEFInd 的文件。此处假定您的 ESP 分区被挂载到 /boot/efi 并且您希望将 rEFInd 存放在 /boot/efi/EFI/refind。

2. 将可执行文件、配置文件和资源文件复制到 ESP

    ```
    cp /usr/share/refind/refind_x64.efi /boot/efi/EFI/refind/refind_x64.efi
    cp /usr/share/refind/refind.conf-sample /boot/efi/EFI/refind/refind.conf
    cp -r /usr/share/refind/{icons,fonts,drivers_x64} /boot/efi/EFI/refind/
    ```
3. 编辑刚才复制的配置文件。该文件有详细的注释。默认情况下，rEFInd 会在您的驱动器中寻找 EFISTUB 内核，所以您可能不需要做任何更改就能启动。

4. 如果需要定制内核引导选项，复制示例配置文件到你的内核的目录。编辑该文件并为您的根分区输入正确的 PARTUUID 和 rootfstype （可以使用 blkid 和 lsblk -f）.

    `cp /usr/share/refind/refind_linux.conf-sample /boot/refind_linux.conf`

    >Tip: refind_linux.conf 的每一行都会被显示为一个子菜单项。按下 + 、 Insert 或 F2 来展开子菜单.
5. 使用 efibootmgr 创建一条 UEFI 启动项（更改 X 、Y 使其指向您的 ESP 分区）。 参见 efibootmgr 的 man 手册.

    `efibootmgr -c -d /dev/sdX -p Y -l /EFI/refind/refind_x64.efi -L "rEFInd"`

#### 实验：efibootmgr

efibootmgr 用于修改EFI启动管理器。我主要用来修改启动顺序
1. efibootmgr

    ```
BootCurrent: 0002
Timeout: 1 seconds
BootOrder: 0002,0000,0001
Boot0000* Windows Boot Manager
Boot0001* rEFInd Boot Manager
Boot0002* ubuntu
```

2. sudo efibootmgr -o 0001,0000,0000

3. 启动后可见rEFInd启动管理器 


### 在已有的 Windows UEFI 安装中使用 rEFInd

rEFInd 兼容 UEFI Windows 安装时创建的 EFI 系统分区，因此没有必要创建或格式化另一个 FAT32 分区。只需挂载 Windows 的 ESP 并像往常一样安装 rEFInd。默认情况下，rEFInd 的自动检测功能应该识别任何现有的 Windows 引导程序。 
