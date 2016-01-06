
# UEFI Secure Boot 实现

Microsoft, however, included a requirement in its Windows 8 certification program that vendors ship computers with Secure Boot enabled. As a practical matter, this means that vendors must include Microsoft's keys on their computers, and unless vendors include other keys, only boot loaders signed by Microsoft will work.  
微软的Windows 8认证程序里包含一个要求：厂商的计算机需要支持Secure Boot。作为一个现实的问题，这就意味着厂商必须在他们的电脑里带有微软的密钥；除非还有其他密钥，否则只有经过微软签名的boot loader才能工作。

幸运的是，微软已经与Verisign合作管理boot loader签名。向Verisign支付99$后软件经销商就可以获得二进制文件签名。更确切的，微软使用一个密钥签名第三方二进制文件，使用另一个密钥签名自家的二进制文件。

此外微软要求x86和x86-64计算机提供方法可以完全禁用Secure Boot，用户控制这个过程。（ARM用户就不这么幸运，微软要求在带有Windows 8 log的ARM系统上Secure Boot不能禁用）

为了使用计算机，有三种途径：

1. 禁用 Secure Boot
2. 使用一个经过签名的Boot Loader
  - Fedora 的 Shim 
  Shim 支持 
   Secure Boot keys - Shim 认同固件预置的密钥，或者用户创建的。
   Shim keys - 自己编译时预置的密钥。一个发行商可以使用这个密钥签名自己的boot loader和内核。
   MOK - Machine Owner Key。

  - Linux Foundation 的 PreLoader
原理：
a) PreLoader是一个已经获得签名的EFI启动管理器
通常首次启动PreLoader会调用HashTool对其它EFI（由用户选择）摘要并保存
启动后PreLoader比对EFI镜像的摘要，如果匹配则载入
b) rEFInd添加启动目录选项时不做预判
用户选完系统后启动，如果不符合secure boot，失败返回

3. 修改密钥


## Secure Boot Key 类型

Database Key (db)
这是您最有可能想到的安全启动的密钥类型，因为它是用来签名或验证那些你要运行二进制文件（boot loader，boot manager，shell，drivers等）。大多数计算机都会有两个安装好的微软密钥。一个微软用于自己的软件，另一个用于其他签署的第三方软件，如Shim，PreLoader。一些计算机也保有计算机制造商或其他合作方创建的密钥。Canonical（Ubuntu Linux分布的创造者）已经设法将她们的密钥嵌入在许多计算机的固件中。正如此描述所暗示的，一个重要的事实，该数据库可以有多个密钥。注意，数据库可以包含公钥和散列值（描述单个二进制文件）。

Database Blacklist Key (dbx)

Key Exchange Key (Key)
当输入密钥进数据库时，KEK用于签名密钥使固件认为他们有效并接受他们。没有KEK，固件将没有办法知道一个新的密钥是有效的或是由恶意软件提供的。因此，在KEK的缺失的情况下，安全启动将是一个笑话或要求数据库保持不变。电脑经常保有两个KEKs，一个来自微软，一个从主板制造商。这使任何一方发出更新。

Platform Key(PK)
平台密钥（PK）在Secure Boot里是最高级别的安全密钥，它提供一个类似KEK的功能。UEFI Secure Boot支持单一的PK，这是通常由主板制造商提供的。因此，只有在主板制造商对电脑全程控制。控制Secure Boot过程的一个重要部分就是替换你自己版本的PK。

Machine Owner Key (MOK)
