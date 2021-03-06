#EDK II 配置

## 环境

个人系统 Ubuntu 14.04 LTS, 64-bit

1. 安装 gcc nasm

    `sudo apt-get install gcc nasm build-essiontial uuid-dev` 

    安装后当前 gcc 版本 4.8.4

2. 下载 EDK2

    `git clone https://github.com/tianocore/edk2`

## 配置

**如果严格按照《UEFI原理与编程》的步骤执行下去是跑不起来的，可能写书到现在EDK也有变更了吧。至于为什么行？为什么不行？暂时还没有搞清楚。（缺乏一个SecMain，至于SecMain这个程序如何生成，如何运作都不清楚）**

1. 配置文件

    ````bash
    cp ./BaseTools/Conf/tools_def.template ./Conf/tools_def.txt
    cp ./BaseTools/Conf/build_rule.template ./Conf/build_rule.txt
    cp ./BaseTools/Conf/FrameworkDatabase.template ./Conf/FrameworkDatabase.db
    cp ./BaseTools/Conf/target.template ./Conf/target.txt
    ````
 
    Conf/target.txt 
    ````bash
    ACTIVE_PLATFORM       = EmulatorPkg/EmulatorPkg.dsc
    TARGET                = DEBUG 
    TARGET_ARCH           = X64 
    TOOL_CHAIN_CONF       = Conf/tools_def.txt 
    TOOL_CHAIN_TAG        = GCC48 
    MAX_CONCURRENT_THREAD_NUMBER = 4
    BUILD_RULE_CONF = Conf/build_rule.txt
    ```` 
    > 最新版本的UnixPkg已经放弃了，使用EmulatorPkg就可以完成相同功能

2. 编译工具链
    ````bash
    cd BaseTools
    make
    ````

3. 编译UEFI模拟器

    ````bash
    source edksetup.sh

    EmulatorPkg/build.sh
    ````

4. 运行模拟器
    ````bash
    EmulatorPkg/build.sh run
    ````

## OVMF 的制作和使用

OVMF (Open Virtual Machine Firmware，开放虚拟机固件)是用于虚拟机上UEFI固件

1. 编译

    `build -a X64 -p OvmfPkg\OvmfPkgX64.dsc`

2. 在虚拟机中使用OVMF

    `qemu-system-x86_64 -bios "OVMF.fd" -M "pc" -m 256 -cpu "qemu64" -vga cirrus -serail vc -parallel vc -name "UEFI" -boot order=dc`
