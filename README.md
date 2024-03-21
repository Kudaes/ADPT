# Description

Another Dll Proxying Tool is exactly what it sounds like, another tool that allows you to automate the exploitation of dll hijack/sideloading opportunities. The goal was to create a simple tool for lazy people like me, meaning that I could abuse this hijack opportunities without the need to:
* Open Api Monitor or reverse anything in order to find out which exported functions from the original dll are being called in the first place.
* Use GHidra or any other reversing tool in order to obtain any function's signature (in/out parameters and so on).
* Translate C types and structs to Rust in order to recreate those exported function definitions.
* Run my payload on DllMain.

With just a little bit of assembly code you can avoid all of those annoying steps, making the exploitation of this hijack opportunities pretty fast and simple. Besides that, ADPT comes with a few additional features that I've found useful:
* Proxied exported functions also keep the original ordinals values, meaning that they can be called that way instead of by name.
* You can run your payload in the calling thread instead of spawning a new one, allowing you to hijack the program execution. This is useful in some cases to prevent the process from dying.
* The payload can be run on a separate thread either by using `std::thread` or using a native method (`NtCreateThreadEx`). IDK why would this be useful, but whatever.

The "bad" news are:
* You still need to use Procmon like tools to identify the hijack opportunity.
* Your payload has to be written in Rust :) (or you could write it in any other language, compile it to a dll and use [Dinvoke_rs](https://github.com/Kudaes/DInvoke_rs) to map it into the process...).
* This tool only supports 64 bits dlls.

# Structure 

This tool contains three different projects:
* `Generator` is the main one and its goal is to programmatically create the dlls needed to automate the exploitation of the hijack opportunities.
* `ExportTracer` is a template project that is used to create a dll that will trace the exported functions called by the vulnerable binary. This allows you to identify in which exported function put your payload code.
* Once we have find out which exported function from the original dll we want to hijack, `ProxyDll` is used as a template project in order to generate the final dll, allowing you to add your payload code on it.

All of these projects must be compiled on `release` mode. Initally, both `ExportTracer` and `ProxyDll` will be empty, so you just need to compile `Generator` in order to start using the tool.
I'm using relative paths within this tool, so keep the three projects in the same directory to prevent failures. 

# Usage 
A while ago [I commented on Twitter](https://twitter.com/_Kudaes_/status/1648749432635105280) about what I called a "delayed" dll sideloading opportunity on `gdi32full.dll`. This dll, after some specific actions, will delayed-import the `TextShaping` dll, creating all sort of hijacking opportunities. In order to prove the ADPT usage, I'll show you how to exploit this dll sideload on ProcessHacker (which is one of the countless binaries that suffer from this delayed dll sideloading thing).

First, we need to figure out which TextShaping.dll's (which is by default located at `C:\Windows\System32\textshaping.dll`) exported functions are being called from ProcessHacker. To do so, we use `Generator` to create a tracing dll:

	C:\Users\User\Desktop\ADPT\Generator\target\release> generator.exe -m trace -p C:\Windows\System32\TextShaping.dll

This command will generate the code and files required by the `ExportTracer` project. Once completed, compile `ExportTracer` on `release` mode, which should generate the file `.\ExportTracer\target\x86_64-pc-windows-msvc\release\exporttracer.dll`. Rename this dll to `TextShaping.dll` and plant it on ProcessHacker directory. Then, just fire up ProcessHacker. The tracer dll will log each one of the called exported functions to a log file, which by default will be written to `C:\Windows\Temp\result.log`. You can change the location of this log file at the time of creating the tracer dll by using the flag `-l`.

The log file will contain one line for each called exported function, allowing you to obtain the name of those functions and in which order they are being called. Below you can see an example of this log file:

![Called functions log file example.](/Images/LogFile.PNG "Called functions log file example.")

With that info, you just need to indicate to the `Generator` the exported function that you want to use in order to run your payload. I'm going to use the first function that has been called, `ShapingCreateFontCacheData`: 

	C:\Users\User\Desktop\ADPT\Generator\target\release> generator.exe -m proxy -p C:\Windows\System32\TextShaping.dll -e ShapingCreateFontCacheData

Similarly to the previous command, this one will create the files required by the `ProxyDll` template project. Once the command has been completed, you can add your payload code in `.\ProxyDll\src\lib.rs:payload_execution()`. By default, the payload is just an infinite loop, which allows you to check that the sideloading has been successful by inspecting the process' threads. But before that, remember to compile the `ProxyDll` project on `release` mode, which will generate the file `.\ProxyDll\target\x86_64-pc-windows-msvc\release\proxydll.dll`. Once again, rename that file to `TextShaping.dll` and plant it on the ProcessHacker directory. Run ProcessHacker one more time and check that the new thread running the infinite loop has been spawned.

![Payload running on a new thread.](/Images/PH.PNG "Payload running on a new thread.")

As it can be seen, our payload is running on the thread with TID `4032`. The payload will run just once. All the exported functions, including the one used to run the payload, are in the end proxied to the corresponding function of the original `TextShaping` dll, allowing the process to run normally. I mean, as any other dll proxying tool would do. Just check the `Modules` tab in PH to see that both dlls are loaded in the process:

![Dll proxying going on.](/Images/Proxy.PNG "Dll proxying going on.")

Finally, some binaries will terminate the process if you dont hijack the calling thread. To prevent them from doing so, the current thread can be hijacked by using the flag `-c`. In that case, the hijacked exported function won't spawn a new thread to run the payload, but instead it will be run in on the current thread, preventing it from reaching the process termination point.

# Considerations
Some issues may arise when trying to use this tool, but in my experience they are simple to fix or circumvent:
* If at the time of compiling the tracer or proxy dll you are getting `error LNK2005: symbol already defined` error messages from the linker, just uncomment the line 5 of the `.cargo\config` file and try again.
* If for any reason you need to statically link the C runtime in your dlls, [check this out](https://github.com/Kudaes/rust_tips_and_tricks?tab=readme-ov-file#vcruntime).

If you find any other issue, report it to me!