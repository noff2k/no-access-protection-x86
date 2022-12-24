## no-access-protection-x86
This program is a rewritten version of the [NO_ACCESS_Protection](https://github.com/weak1337/NO_ACCESS_Protection) by [weak1337](https://github.com/weak1337) tool from x64 to x86, which is a tool for protecting a Windows executable by encrypting its code and setting up an exception handler to decrypt the code when it is accessed.

It prevents: 
* Basic Signature Ccanning (access violation + rip check)
* Cheat Engine Veh Debugger
* Full process dumping (since you can encrypt the pages again)
