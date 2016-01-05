
# UEFI Secure Boot Guide

 Secure Boot is a technology where the system firmware checks that the system boot loader is signed with a cryptographic key authorized by a database contained in the firmware. With adequate signature verification in the next-stage boot loader(s), kernel, and, potentially, user space, it is possible to prevent the execution of unsigned code.

Secure Boot is a form of Verified Booting. Boot path validation is also part of other technologies such as Trusted Boot. Boot path validation is indepedent of secure storage of cryptographic keys and remote attestation. 

## UEFI Secure Boot

 UEFI Secure Boot is the boot path validation component of the UEFI specification (Unified Extensible Firmware Interface)as of version 2.3. Roughly speaking, it specifies the following:

   - a programming interface for cryptographically protected UEFI variables in non-volatile storage,
   - how the trusted X.509 root certificates are stored in UEFI variables,
   - validation of UEFI applications (boot loaders and drivers) using AuthentiCode signatures embedded in these applications, and
   - procedures to revoke known-bad certificates and application hashes. 

UEFI Secure Boot does not require specialized hardware, apart from non-volatile (flash) storage which can be switched from read-write mode to read-only mode during system boot. This storage has to be used to store the UEFI implementation itself and some of the protected UEFI variables (including the trusted root certificate store).

From a user point of view, a system which has enabled UEFI Secure Boot and which is confronted with a tampered boot path simply stops working until UEFI Secure Boot is disabled or a signed next-stage boot loader is available on boot media. (Figure 1.1, “Typical error message from UEFI Secure Boot” shows a typical error message.) Similarly, operating system installers without a cryptographically valid signature do not run and result in an error message. Users are not offered a way to override the boot loader decision to reject the signature, unlike the similar scenario with web server certificates. No certificate issuer information is provided to the user.

````
┌────────── Secure Boot Violation ──────────┐
│                                           │
├───────────────────────────────────────────┤
│ Invalid signature detected. Check Secure  │
│          Boot Policy in Setup             │
│                                           │
│                                           │
│                   [OK]                    │
└───────────────────────────────────────────┘
````
Figure 1.1. Typical error message from UEFI Secure Boot

UEFI Secure Boot does not prevent the installation or removal of second-stage boot loaders or require explicit user confirmation of such changes. Signatures are verified during booting, and not when the boot loader is installed or updated. Therefore, UEFI Secure Boot does not stop boot path manipulations. It only prevents the system from executing a modified boot path once such a modification has occurred, and simplifies their detection. 

## UEFI Secure Boot Implementation

 The Fedora Secure Boot implementation includes support for two methods of booting under the Secure Boot mechanism. The first method utilizes the signing service hosted by Microsoft to provide a copy of the shim bootloader signed with the Microsoft keys. The second method is a more general form of the first, wherein a site or user can create their own keys, deploy them in system firmware, and sign their own binaries. 

### 
