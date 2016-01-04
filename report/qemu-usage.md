#QEMU

## qemu-img
当使用 QEMU 时，可以用磁盘文件代替硬盘。QEMU 支持几种不同的文件格式用于模拟磁盘，最有用的是原始磁盘镜像。

可以使用 qemu-img 命令生成磁盘镜像。
该命令有很多选项，但基本使用相当简单：传递给它 create 参数，-f fmt参数来设置格式、文件名和镜像大小。原始镜像（-f raw）对于与其它模拟器交换数据非常有用；而QCOW2(-f qcow2）支持压缩，能够利用相对小的空间生成看上去很大的磁盘。

例如，以下命令将生成 200GiB 的磁盘镜像文件。一开始，该文件占用主机很小的磁盘空间（只有256KiB）；随着使用，逐渐增大。
`qemu-img create -f qcow2 winxp.qcow2 200G`

>qemu-img 命令：允许你创建、转换及修改离线的镜像，它能处理所有QEMU支持的镜像格式。
  >> 警告：永远不要使用qemu-img去修改一个虚拟机或者其它进程正在使用的镜像，这将导致镜像受损。

## qemu-kvm
创建 winxp.qcow2 文件后，我们尝试一下启动虚拟机安装操作系统

`qemu-system-x86_64 -m 2048 -enable-kvm winxp.img -cdrom /work/TomatoWinXP_SP3_V1.0.ISO`

其中，-m 2048 将虚拟机内存调整为2048MiB，-enable-kvm 表示使用KVM进行加速，-cdrom添加光盘。

我们常用的参数

1. cpu相关参数 
    -cpu：指定cpu模型，默认的为qemu64，可以通过“-cpu ？”查询当前支持的cpu模型 
    -smp：设置虚拟机的vcpu个数。后面还可以加cores threads socke
2. 内存相关参数 
    -m:设置虚拟机内存大小，默认单位为MB 
3. 磁盘相关参数 
    -hda、-hdb和cdrom等：设置虚拟机的IDE磁盘和光盘设置 
    -driver：配置驱动器 
    -boot：设置虚拟机的启动选项 
4. 网络相关参数 
    -net nic:为虚拟机创建一个nic网卡 
    -net user:让虚拟机使用不需要管理权限的用户模式网络(user mode network) 
    -net tap:使用host的tap网络接口来帮助guest建立网络 
    -net none:不配置任何网络设备 
5. 图形显示参数 
    -vnc：使用vnc方式显示客户机 
    -vga：设置虚拟机中的vga显卡类型，默认为“-vga cirrus” 
    -nographic：关闭qemu的图形化界面输出 
6. 其他常用参数 
    -h:显示帮助手册 
    -noreboot:guest执行reboot操作时，系统关闭后退出qemu-kvm，而不会再启动虚拟机 
    -no-shutdown:虚拟机shutdown后，系统关闭后，不退出qemu-kvm进程，保持这个进程存在，他的monitor仍然可以用 
    -loadvm:加载快照状态，与monitor中的“loadvm”命令类似 
    -nodefaults:不创建默认的设备。默认会创建一些显卡、串口、控制台等设备 
    -readconfig:从文件中读虚拟机设备的配置信息 
    -writeconfig：将虚拟机的配置信息写到文件中 
    -nodedefconfig:不加载默认的配置文件。默认会加载/use/local/share/qemu下的文件 
    -no-user-config:不加载用户自定义的配置文件 

----
更多关于qemu-kvm参数

1. man qemu 
2. http://qemu.weilnetz.de/qemu-doc.html 
3. http://wiki.qemu.org/download/qemu-doc.html 
4. http://wiki.gentoo.org/wiki/QEMU/Options 
5. http://wiki.libvirt.org/page/QEMUSwitchToLibvirt 
