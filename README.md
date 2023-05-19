## no-access-protection-x86
This program is a rewritten version of the [NO_ACCESS_Protection](https://github.com/weak1337/NO_ACCESS_Protection) by [weak1337](https://github.com/weak1337) tool from x64 to x86. It encrypts the text section and set the protection to NO_ACCESS. The pages will be decrypted on first access. If the RIP, that referenced the memory, is outside of a valid module it will fail and will crash the process after some time. With this they can prevent:
* Basic Signature Scanning (access violation + rip check)
* Cheat Engine Veh Debugger
* Full process dumping (since you can encrypt the pages again)

![](https://i.imgur.com/P2OyIrg.jpeg)
