# UEFI Secure Boot

原文链接 https://technet.microsoft.com/en-us/library/hh824987.aspx

挑一些重点的翻译成中文

Secure Boot is a security standard developed by members of the PC industry to help make sure that your PC boots using only software that is trusted by the PC manufacturer.

When the PC starts, the firmware checks the signature of each piece of boot software, including firmware drivers (Option ROMs) and the operating system. If the signatures are good, the PC boots, and the firmware gives control to the operating system.

PC启动后，固件检查每个启动软件（包括固件驱动和操作系统）。如果签名是好的，PC启动，固件将控制权交给操作系统。

## Manufacturing Requirements

Secure Boot requires a PC the meets the UEFI Specifications Version 2.3.1, Errata C or higher.

Secure Boot is supported for UEFI Class 2 and Class 3 PCs. For UEFI Class 2 PCs, when Secure Boot is enabled, the compatibility support module (CSM) must be disabled so that the PC can only boot authorized, UEFI-based operating systems.

Secure Boot does not require a Trusted Platform Module (TPM).
Secure Boot 不是必须需要一个 TPM。

To enable kernel-mode debugging, enable TESTSIGNING, or to disable NX, you must disable Secure Boot. For detailed info for OEMs, see [Windows 8.1 Secure Boot Key Creation and Management Guidance](https://technet.microsoft.com/en-us/library/dn747883.aspx).

## How it works

The OEM uses instructions from the firmware manufacturer to create Secure Boot keys and to store them in the PC firmware. For info, see [Windows 8.1 Secure Boot Key Creation and Management Guidance](https://technet.microsoft.com/en-us/library/dn747883.aspx), [Secure Boot Key Generation and Signing Using HSM (Example)](https://technet.microsoft.com/en-us/library/dn747881.aspx), or contact your hardware manufacturer.

OEM 使用固件制造商提供的指令创建Secure Boot密钥，并将它们存储在PC固件中。

When you add UEFI drivers (also known as Option ROMs), you'll also need to make sure these are signed and included in the Secure Boot database. 

当你添加一个UEFI驱动（也称作可选ROM）时，你也需要确认它们已经签名，并且在Secure Boot的数据库中。

When Secure Boot is activated on a PC, the PC checks each piece of software, including the Option ROMs and the operating system, against databases of known-good signatures maintained in the firmware. If each piece of software is valid, the firmware runs the software and the operating system.

>Secure Boot is based on the Public Key Infrastructure (PKI) process to authenticate modules before they are allowed to execute. These modules can include firmware drivers, option ROMs, UEFI drivers on disk, UEFI applications, or UEFI boot loaders. 

### Signature Databases and Keys

Before the PC is deployed, the OEM stores the Secure Boot databases onto the PC. This includes the signature database (db), revoked signatures database (dbx), and Key Enrollment Key database (KEK) onto the PC. These databases are stored on the firmware nonvolatile RAM (NV-RAM) at manufacturing time.

在电脑部署前，OEM将Secure Boot数据库存储到PC中。这包括签名数据库（db），撤销的签名数据库（dbx），PC上的密钥注册密钥（KEK）。在生产时这些数据库被存储在关键的非易失RAM上。

The signature database (db) and the revoked signatures database (dbx) list the signers or image hashes of UEFI applications, operating system loaders (such as the Microsoft Operating System Loader, or Boot Manager), and UEFI drivers that can be loaded on the individual PC, and the revoked images for items that are no longer trusted and may not be loaded.

The Key Enrollment Key database (KEK) is a separate database of signing keys that can be used to update the signature database and revoked signatures database. Microsoft requires a specified key to be included in the KEK database so that in the future Microsoft can add new operating systems to the signature database or add known bad images to the revoked signatures database.

After these databases have been added, and after final firmware validation and testing, the OEM locks the firmware from editing, except for updates that are signed with the correct key or updates by a physically present user who is using firmware menus, and then generates a platform key (PK). The PK can be used to sign updates to the KEK or to turn off Secure Boot.

OEMs should contact their firmware manufacturer for tools and assistance in creating these databases. For more info, see [Windows 8.1 Secure Boot Key Creation and Management Guidance](https://technet.microsoft.com/en-us/library/dn747883.aspx).

### Boot Sequence

    - After the PC is turned on, the signature databases are each checked against the platform key.

    - If the firmware is not trusted, the UEFI firmware must initiate OEM-specific recovery to restore trusted firmware.

    - If there is a problem with Windows Boot Manager, the firmware will attempt to boot a backup copy of Windows Boot Manager. If this also fails, the firmware must initiate OEM-specific remediation.

    - After Windows Boot Manager has started running, if there is a problem with the drivers or NTOS kernel, Windows Recovery Environment (Windows RE) is loaded so that these drivers or the kernel image can be recovered.

    - Windows loads antimalware software.

    - Windows loads other kernel drivers and initializes the user mode processes.


## Secure Boot and 3rd party signing

### UEFI driver signing

UEFI Drivers must be signed by a CA or key in the db as described elsewhere in the document, or have the hash of the driver image included in db. Microsoft will be providing a UEFI driver signing service similar to the WHQL driver signing service using the Microsoft Corporation UEFI CA 2011. Any drivers signed by this will run seamlessly on any PCs that include the Microsoft UEFI CA. It is also possible for an OEM to sign trusted drivers and include the OEM CA in the db, or to include hashes of the drivers in the db. In all cases a UEFI driver (Option ROM) shall not execute if it is not trusted in the db.

UEFI 驱动必须由CA或者签名数据库中对应的密钥签名，或者存放驱动镜像的hash值到该数据库中。
> the db as described elsewhere in the document 即为签名数据库

Any drivers that are included in the system firmware image do not need to be re-verified. Being part of the overall system image provides sufficient assurance that the driver is trusted on the PC.

Microsoft has this made available to anyone who wants to sign UEFI drivers. This certificate is part of the Windows HCK Secure Boot tests.

### Boot loaders

The Microsoft UEFI driver signing certificate can be used for signing other OSs. For example, Fedora’s Linux boot loader will be signed by it.

This solution doesn’t require any more certificates to be added to the key Db. In addition to being cost effective, it can be used for any Linux distribution. This solution would work for any hardware which supports Windows 8.1 so it is useful for a wide range of hardware.

The UEFI-CA can be downloaded from here: http://go.microsoft.com/fwlink/p/?LinkID=321194. The following links have more information on Windows HCK UEFI signing and submission:
