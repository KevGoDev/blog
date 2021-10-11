+++
author = "Kevin Goyette"
title = "Monitoring filesystem access using hooks on Windows"
date = "2021-09-10"
description = "Here's a presentation of the projects I've worked on."
+++


# The project
This application will target native applications and inject a payload inside them that will then hook every filesystem functions.
To do so, this application will have to be written in C or C++.

# What is a hook anyway?
A program will import functions from different libraries. Let's say we write a Windows application that reads a file and displays its content. 
We need to call a function to read the file, then a function to read its content and a function to display it. 
These functions are already implemented for us by Microsoft, we just need to import and call them. 

Programs will keep information about its imported functions in what is called an **Import Address Table**. 
This import table is kept inside the Portable Executable header(PE32 header).

Let's take the native Windows application *notepad.exe*. We can use CFF Explorer to read its import address table.

![cff](/images/fs_capture/cff_notepad.png)

During runtime, Notepad will import Kernel32.dll, resolve the correct addresses and store them inside its import table.
This is what the import table for Kernel32.dll would look like in memory:

| Function name  | Address in memory |
|----------------|-------------------|
| OpenFile       | 0x1234            |
| ReadFile       | 0x5678            |


A hook consists of injecting the remote process, in this case notepad, and overwrite addresses inside the import address table with our own addresses.

| Function name  | Address in memory |
|----------------|-------------------|
| OpenFile       | 0xA000            |
| ReadFile       | 0xB000            |





{{< rawhtml >}}
<br /><br />
{{< /rawhtml >}}
# Setting up the project
We create a solution containing 3 projects. The injector, the payload and a process helper.


## About: The injector(64-bit)
The injector application is a console or GUI application that will do the following:
1. Ask the user for a target process to inject
2. Find target process
3. Determine from the process architecture whether the process is 32-bit or 64-bit
4. Inject our payload inside the target process using the correct architecture 
5. Create a remote thread on the target process that will execute our payload inside the target process
6. Exit since the payload is now running inside our target process


## About: The payload(32-bit and 64-bit)
The payload is a Dynamic Link Library(dll) that, when attached to a process, 
will find the import address table and overwrite predefined functions with its own functions.
It will hook filesystem api functions with its own functions. Its own functions will log the file access 
and call the original function.

Here's an example of a hooked function:
```c

// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
HANDLE CreateFileW_hook(LPCWSTR Filename, DWORD DesiredAccess, DWORD ShareMode, LPSECURITY_ATTRIBUTES SecAttribs, DWORD CreationDisp, DWORD Flags, HANDLE Template) {
    // We call the original function to get its actual result
    HANDLE handle = original_CreateFileW(Filename, DesiredAccess, ShareMode, SecAttribs, CreationDisp, Flags, Template);
    // We log the file access and its result
    DBG_LOG("[CALL]: Creating/Opening file %ws with handle %p", Filename, handle);
    // We return its expected value
    return handle;
}
```

As we can see, the target process will not see any changed when calling CreateFileW since we keep the original behavior intact.
We simply add a logging function(DBG_LOG) during the function call.

## About: The process helper(32-bit)
Windows loads different internal libraries into memory such as Kernel32.dll. These libraries are available system-wide.
This means if a program imports a function from Kernel32, its address would be valid for any other program on the system. 
There is a catch however, Kernel32 is loaded twice in memory. 

1. The first instance is `"C:\Windows\System32\kernel32.dll"` which is the 64-bit variant.
2. The other instance is `"C:\Windows\SysWOW64\kernel32.dll"` which is the 32-bit variant loaded as part of 
the WOW64 subsystem that runs 32-bit applications on a 64-bit system.


{{< rawhtml >}}
<br />
{{< /rawhtml >}}
# Writing a stub payload
Before starting with the injector, we need a way to know if our payload has succesfully been injected inside the process and ensure
its entry point is executed. 

To do so, we make our payload create a thread in which it prints a debug line inside the system debugger.
We can read the debug output using WinDbg.

```cpp
#include <cstdio>

// Helper macro to print debug information
#define MAX_BUF 512
#define DBG_LOG(fmt, ...) {\
    char buf[MAX_BUF]={0}; \
    sprintf_s(buf, MAX_BUF, "[fs_monitorer][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(buf);\
}

// Main Entry Point
BOOL APIENTRY DllMain(HMODULE module, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DBG_LOG("Injected");
        break;
    }
    return TRUE;
}
```

Our stub payload is now ready. We can start working on the injector.

# Writing the injector
We start by creating a helper class named Process. This class will act as a controller for windows process operations.
A process has a name, an architecture(32-bit or 64-bit) and a process id. We end up with the following class:
```cpp

class Process {
private:
    DWORD id;
    std::wstring name;
    bool m_is_64bit = true;
public:
    Process(std::wstring name, DWORD pid = 0);
    ~Process();

    /// <summary>
    /// Waits until the process is found on the system and assigns its process id
    /// </summary>
    /// <param name="timeout">Time in miliseconds to wait before abandoning. -1 to wait undefinitely</param>
    /// <returns>Process id</returns>
    DWORD wait_for_process(int timeout = -1);

    /// <summary>
    /// Gets the address of LoadLibraryA depending on architecture of remote process
    /// </summary>
    /// <returns>The address of LoadLibraryA. It is not validated.</returns>
    FARPROC get_LoadLibraryA_address();

    /// <summary>
    /// Injects a dll into the process
    /// </summary>
    /// <param name="dll_path">Full path of the dll to inject</param>
    /// <returns>Returns whether it succeeded or not</returns>
    bool inject_dll(const char* dll_path);
    bool is_64bit() { return this->m_is_64bit; }
};
```

The `wait_for_process` method is quite trivial as it uses windows api to find a process by name and return its process id so I will skip it.

I'd like to elaborate instead on `get_LoadLibraryA_address` and `inject_dll`.


The `get_LoadLibraryA_address` method is quite simple if the remote process is 64-bit however it gets tricky if 
it is 32-bit. If the remote process is 32-bit, it won't be able to call a 64-bit function so we need to 
get the LoadLibraryA address from the WOW64 subsystem. 

This is where we call our Process Helper which is a 
32-bit executable file that returns the WOW64 address of LoadLibraryA. 

```cpp
FARPROC Process::get_LoadLibraryA_address() {
    assert(this->id >= 0);
    // If the target process is 64 bit then we simply return the global address of LoadLibraryA
    if (this->m_is_64bit) {
        return GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    }
    // The target process is 32-bit so we must call our process helper to get the WOW64 address of LoadLibraryA
    // We get the working directory to be able to call our process helper
    char working_dir[MAX_BUF] = { 0 };
    if (!GetCurrentDirectoryA(MAX_BUF-1, working_dir)) {
        DBG_LOG("[ERROR]: Could not retrieve current working directory while resolving LoadLibraryA. Aborting...\n");
        return NULL;
    }
    
    // We create a new process for the ProcessHelper32
    std::string exe_path = std::string(working_dir) + "\\ProcessHelper32.exe";
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    ZeroMemory(&process_info, sizeof(process_info));
    BOOL process_created = CreateProcessA(exe_path.c_str(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, &startup_info, &process_info);
    if (process_created) {
        // We wait for the process to return
        WaitForSingleObject(process_info.hProcess, INFINITE);
        DWORD process_return = 0;
        BOOL res = GetExitCodeProcess(process_info.hProcess, &process_return);
        if (!res) {
            DBG_LOG("Error while getting process returned value: %d\n", GetLastError());
        }
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);

        // We return the address given by ProcessHelper32
        DBG_LOG("ProcessHelper32 returned %04x\n", process_return);
        return (FARPROC)process_return;
    }
    else {
        DBG_LOG("Could not call ProcessHelper32 at (%s), received error code: %d. Aborting...\n", exe_path.c_str(), GetLastError());
        return NULL;
    }
}
```


---
The inject method writes the full path of the dll inside of the remote process memory. 
It then creates a thread inside the remote process using the address of the LoadLibraryA function as
the entry point of the thread.

This will effectively make the remote process execute the following:  `LoadLibraryA(dll_path)`
```cpp
bool Process::inject_dll(const char* dll_path) {
    assert(this->id >= 0);
    DBG_LOG("Injecting %s on pid %d\n", dll_path, this->id);
    // We open a handle to the remote process
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, this->id);
    SIZE_T written_bytes = 0;
    // We resolve the address of LoadLibraryA
    PTHREAD_START_ROUTINE loadlibrary_address = (PTHREAD_START_ROUTINE)this->get_LoadLibraryA_address();
    if (loadlibrary_address <= 0) {
        DBG_LOG("Address of LoadLibraryA is invalid. Addr: %p\n", loadlibrary_address);
        return false;
    }
    // We write the full path of the dll inside the remote process (+1 for null byte)
    LPVOID dllpath_address = VirtualAllocEx(process_handle, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(process_handle, dllpath_address, dll_path, strlen(dll_path) + 1, &written_bytes);
    // We create a thread inside the remote process that executes our injected dll (stack size = 1024 bytes, doesn't really matter in our case)
    CreateRemoteThread(process_handle, NULL, 1024, loadlibrary_address, dllpath_address, 0, 0);
    return true;
}
```
---

 


## Triggering the antivirus

![virus_achv](/images/fs_capture/virus_achv.png)

![virus_achv](/images/fs_capture/virus.png)

Of course Microsoft Windows Defender won't be too happy about the strange behavior of our application, understandably.

I added my project's directory to Defender's exclusions.


 

# Writting the process helper
The process helper is trivial to build, we simply get the address of LoadLibraryA and return it. 
Since the applicatiion is 32-bit that address will be for the WOW64 subsystem.

```cpp
#include <cstdio>
#include <windows.h>

int main(int argc, char** argv){
    DWORD addr = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    printf("Found Kernel32.LoadLibraryA at %p\n", addr);
    return addr;
}

```



# Testing the injector
We can now test the injector on any applications that is 64-bit. I will take notepad.exe as an example.

We run the injector and specify Notepad.exe as the target process. 
We then open WinDbg, in my case I'll use [DebugView++](https://github.com/CobaltFusion/DebugViewPP) which 
will allow me to filter through the logs more easily.

This is the output from the console:
```
C:\Users\kevin\Desktop\projects\fs_monitorer\bin>injector.exe
[fs_monitorer][main] Payload path for 32bit: C:\Users\kevin\Desktop\projects\fs_monitorer\bin\payload32.dll
[fs_monitorer][main] Payload path for 64bit: C:\Users\kevin\Desktop\projects\fs_monitorer\bin\payload64.dll
[fs_monitorer][main] Process to monitor(Example: Notepad.exe): Notepad.exe
[fs_monitorer][main] Waiting for process 'Notepad.exe'.
[fs_monitorer][Process::wait_for_process] Found process Notepad.exe with PID 6096
[fs_monitorer][main] Injecting in 64bit mode
[fs_monitorer][Process::inject_dll] Injecting C:\Users\kevin\Desktop\projects\fs_monitorer\bin\payload64.dll on pid 6096
[fs_monitorer][main] Injection result: Success
[fs_monitorer][main] Press any key to exit...
C:\Users\kevin\Desktop\projects\fs_monitorer\bin>

```

But more importantly this is the output from DebugView++:
```
1   3.104851    6096    Notepad.exe [fs_monitorer][DllMain] Injected
```

This means our payload was succesfully injected and its code has been executed. The injector works, at least for 64-bit.

We can also test on a 32-bit app, there is a 32-bit windows app located at `C:\Windows\SysWOW64\nslookup.exe`.

We run our test on `nslookup.exe`:
```
C:\Users\kevin\Desktop\projects\fs_monitorer\bin>injector.exe
[fs_monitorer][main] Payload path for 32bit: C:\Users\kevin\Desktop\projects\fs_monitorer\bin\payload32.dll
[fs_monitorer][main] Payload path for 64bit: C:\Users\kevin\Desktop\projects\fs_monitorer\bin\payload64.dll
[fs_monitorer][main] Process to monitor(Example: Notepad.exe):
nslookup.exe
[fs_monitorer][main] Waiting for process 'nslookup.exe'.
[fs_monitorer][Process::wait_for_process] Found process nslookup.exe with PID 18376
[fs_monitorer][main] Injecting in 32bit mode
[fs_monitorer][Process::inject_dll] Injecting C:\Users\kevin\Desktop\projects\fs_monitorer\bin\payload32.dll on pid 18376

Found Kernel32.LoadLibraryA at 760924A0
[fs_monitorer][Process::get_LoadLibraryA_address] ProcessHelper32 returned 760924a0

[fs_monitorer][main] Injection result: Success
[fs_monitorer][main] Press any key to exit...
C:\Users\kevin\Desktop\projects\fs_monitorer\bin>
```

Output from DebugView++
```
1   114.787226  18376   nslookup.exe    [fs_monitorer][DllMain] Injected
```
---

The foundations of our app is working. We can now work on the hooking process inside our payload.

 

# Writing the payload































{{< rawhtml >}}
<div style="margin-bottom: 16rem;margin-top: 16rem;"></div>
{{< /rawhtml >}}





















