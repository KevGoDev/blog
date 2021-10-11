+++
author = "Kevin Goyette"
title = "Monitorer les accès au système de fichiers en utilisant des hooks sur Windows"
date = "2021-09-10"
description = ""
+++


# Le projett
This application will target native applications and inject a payload inside them that will then hook every filesystem functions.
To do so, this application will have to be written in C or C++.

Cette application ciblera les applications natives et y injectera un payload qui appliquera ensuite un hook toutes les fonctions du système de fichiers.
Pour ce faire, cette application devra être écrite en C ou C++.

# Qu'est-ce qu'un hook?
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

Microsoft Windows Defender isn't too happy about the strange behavior of our application, understandably.

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

 

### The IAT hooking function
This section is quite heavy. We start with the IAT hooking function. 
The IAT hooking function is based of the following Microsoft documentation pages:
* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#delay-load-import-tables-image-only
* https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2

For more documentation, I had to read windows header files, mainly `winnt.h` , inside of visual studio to get a better understanding of their data structures.

This is the code for our IAT hooking function, it takes the name of the function we want to hook 
and the address of its hook function(our own function).

The function then returns the address of the original function we hooked.

Here is the IAT hooking function:

```cpp
// This value is used during the IAT hooking process to make sure the ordinal is valid
#if _WIN64
    #define INVALID_ORDINAL 0x8000000000000000
#else
    #define INVALID_ORDINAL 0x80000000
#endif

/// <summary>
/// Reroutes a function to another function.
/// </summary>
/// <param name="function_name">Name of the function to reroute.</param>
/// <param name="addr_new_fn">Address of the new function we want function_name to point to.</param>
/// <returns>Returns the original address of the function to reroute. Returns NULL if we couldn't find the function.</returns>
DWORD_PTR hook_IAT(std::string function_name, void* addr_new_fn) {
    // Get the base address of the current module
    LPVOID image_base = GetModuleHandleA(NULL);
    if (image_base == NULL) {
        DBG_LOG("[ERROR]: Image base is null");
        return NULL;
    }
    // Read PE Headers from image
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
    PIMAGE_DOS_HEADER dos_headers = (PIMAGE_DOS_HEADER)image_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_base + dos_headers->e_lfanew);
    // Get imports descriptor
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = NULL;
    IMAGE_DATA_DIRECTORY imports_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imports_directory.VirtualAddress + (DWORD_PTR)image_base);
    // Iterate through each descriptor(module) and get their import table
    while (import_descriptor->Name != NULL) {
        // Load current module to get its import table
        LPCSTR library_name = (LPCSTR)import_descriptor->Name + (DWORD_PTR)image_base;
        HMODULE library = LoadLibraryA(library_name);
        DBG_LOG("Processing module %s", library_name);
        if (library) {
            // Read import table from current module
            PIMAGE_THUNK_DATA orig_first_thunk = NULL, first_thunk = NULL;
            orig_first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)image_base + import_descriptor->OriginalFirstThunk);
            first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)image_base + import_descriptor->FirstThunk);
            while (orig_first_thunk->u1.AddressOfData != NULL) {
                PIMAGE_IMPORT_BY_NAME function_import = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)image_base + orig_first_thunk->u1.AddressOfData);
                // We must be careful about the validity of AddressOfData
                if (orig_first_thunk->u1.AddressOfData <= INVALID_ORDINAL) {
                    DBG_LOG("\tFound function: %s", function_import->Name);
                }
                // Check if address of data is valid, some imports will set most significant bit to 1 which we can't read
                if (orig_first_thunk->u1.AddressOfData <= INVALID_ORDINAL && std::string(function_import->Name).compare(function_name) == 0) {
                    // We need to set the import table protection to RW in order to edit it
                    DWORD old_protection = 0, void_protect = 0;
                    VirtualProtect((LPVOID)(&first_thunk->u1.Function), 8, PAGE_READWRITE, &old_protection);
                    // We save original address of the hooked function
                    DWORD_PTR original_address = first_thunk->u1.Function;
                    // We hook the function
                    first_thunk->u1.Function = (DWORD_PTR)addr_new_fn;
                    // We restore region protection on the import table
                    VirtualProtect((LPVOID)(&first_thunk->u1.Function), 8, old_protection, &void_protect);
                    return original_address;
                }
                orig_first_thunk++;
                first_thunk++;
            }
        }
        import_descriptor++;
    }
    return NULL;
}
```


### Our first hook
Back at the beginning of this post, we opened notepad inside of CFF Explorer to see its imports:

![cff](/images/fs_capture/cff_notepad.png)

 

CreateFileW seems like a good candidate for our first hook. Let's copy this function's signature 
using its documentation page on Microsoft:

https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew

The following code contains the prototype definition for CreateFileW, a global variable to save its original address,
the hook function and our main thread.

```cpp
// Definition for the CreateFileW prototype
typedef HANDLE(*proto_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

// Global variable that stores the original address of CreateFileW
proto_CreateFileW original_CreateFileW = nullptr;

// Hook function for CreateFileW with logging, we must keep the original signature
HANDLE CreateFileW_hook(LPCWSTR filename, DWORD des_acces, DWORD shr_mode, LPSECURITY_ATTRIBUTES sec_atr, DWORD creation, DWORD flags, HANDLE htemplate) {
    // We call the original function to get the actual result
    HANDLE handle = original_CreateFileW(filename, des_acces, shr_mode, sec_atr, creation, flags, htemplate);
    // We log the filename of the file we performed the operation on
    DBG_LOG("[CALL]: Creating/Opening file %ws with handle %p", filename, handle);
    // We return the original function's result
    return handle;
}

/// <summary>
/// Prints to Debug status information about the hooking process of a function.
/// </summary>
/// <param name="function_name">Name of the function we attempted to hook.</param>
/// <param name="old_addr">Original address returned by hook_IAT.</param>
void dbgPrintHookStatus(std::string function_name, void* old_addr) {
    if (old_addr != NULL) {
        DBG_LOG("[LOG]: Hooked %s, old address: %p", function_name.c_str(), old_addr);
    }
    else {
        DBG_LOG("[ERROR]: Failed to hook %s", function_name.c_str());
    }
}

// Main thread to hook iat function. Thread terminates after the hooking process is done
DWORD WINAPI main_thread(void*) {
    // We save the original address inside our global variable, the function should be hooked
    original_CreateFileW = (proto_CreateFileW)hook_IAT("CreateFileW", CreateFileW_hook);
    // We print debug information about our hook result
    dbgPrintHookStatus("CreateFileW", (void*)original_CreateFileW);
    return TRUE;
}

// Main Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DBG_LOG("Injected");
        CreateThread(nullptr, 0, main_thread, hModule, 0, nullptr);
        break;
    }
    return TRUE;
}
```

### Testing our first hook
We run our injector, specify our remote target and take a look inside DebugView++:

```
62  3026.952042 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: QueryPerformanceCounter
63  3026.952062 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: MultiByteToWideChar
64  3026.952083 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: LocalReAlloc
65  3026.952104 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: UnmapViewOfFile
66  3026.952124 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: GetFileInformationByHandle
67  3026.952148 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: CreateFileMappingW
68  3026.952169 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: MapViewOfFile
69  3026.952189 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: LocalAlloc
70  3026.952210 1484    Notepad.exe [fs_monitorer][hook_IAT]    Found function: CreateFileW
71  3026.952254 1484    Notepad.exe [fs_monitorer][dbgPrintHookStatus] [LOG]: Hooked CreateFileW, old address: 00007FF955732ED0
```

It seems like our payload hooked `CreateFileW` but we must make sure it is actually hooked. 
Let's open a file with notepad and see if it will print the name of the file inside our debug view:

```
[fs_monitorer][CreateFileW_hook] [CALL]: Creating/Opening file C:\Users\kevin\Desktop\projects\fs_monitorer\test.txt with handle 0000000000000484
```

Our hook seems to work! It printed the name of the file that was opened with notepad.
We can now hook any function imported by a program.

### Redirecting CreateFileW
Our current hook currently logs information but we can actually change the behavior of the function.

Let's say we have these two files on our system:
1. A file named `secret.txt` that contains the string `SECRET123`.
2. A file named `fake_secret.txt` that contains the string `NOT_A_SECRET`.

Let's modify our hook to block access to secret.txt and instead open the file fake_secret.

```cpp
HANDLE CreateFileW_hook(LPCWSTR filename, DWORD des_acces, DWORD shr_mode, LPSECURITY_ATTRIBUTES sec_atr, DWORD creation, DWORD flags, HANDLE htemplate) {
    HANDLE handle = NULL;
    const LPCWSTR secret_file = L"C:\\Users\\kevin\\Desktop\\projects\\fs_monitorer\\secret.txt";
    const LPCWSTR fake_file = L"C:\\Users\\kevin\\Desktop\\projects\\fs_monitorer\\fake_secret.txt";
    // We check if the file being opened is our secret file
    if (lstrcmpiW(filename, secret_file) == 0) {
        // We give it the fake secret file
        handle = original_CreateFileW(fake_file, des_acces, shr_mode, sec_atr, creation, flags, htemplate);
    }
    else {
        // We call the original function to get the actual result
        handle = original_CreateFileW(filename, des_acces, shr_mode, sec_atr, creation, flags, htemplate);
    }   
    // We log the filename of the file we performed the operation on
    DBG_LOG("[CALL]: Creating/Opening file %ws with handle %p", filename, handle);
    // We return the original function's result
    return handle;
}
```

We now inject into notepad again and open our secret file with notepad. 
The expected result inside notepad would be `SECRET123` but since we redirected 
the file to our fake secret file we get the following result:

![secret](/images/fs_capture/secret.png)

Notepad thinks it opened `secret.txt` while in fact it opened `fake_secret.txt`. 
So our hooks can not only log information about function calls but we can also alter the 
behavior of these functions.

Let's revert back to simply logging as the scope of this project is to simply log filesystem access.

We can now find more filesystem api functions to hook.

 

### Hooking other filesystem api functions
We can now hook other filesystem api functions using the same concept. 
The only issue is when we handle [named pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes). 
Our function has a handle but not information on it so I had to write a function to get the pipe's name.
This was a bit more complicated as there is no official documentation on the subject by Microsoft. 
I had to get my documentation from [ntinternals.net](http://undocumented.ntinternals.net/index.html).

The following code is how I managed to retrieve the name of a named pipe using its handle:
```cpp
/* NT function definition for GetFilePath */
typedef NTSTATUS(*NtQueryObject_proto)(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
NtQueryObject_proto ResolvedNtQueryObject = nullptr;

/* Undocumented API: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FOBJECT_INFORMATION_CLASS.html */
#define ObjectNameInformation 1

/// <summary>
/// Gets the file path from a file/pipe handle
/// </summary>
/// <param name="hFile">Handle to the file/pipe</param>
/// <returns>A heap allocated wchar array</returns>
LPWSTR GetFilePath(HANDLE hFile) {
    void* temp_obj_name = malloc(MAX_BUF);
    ZeroMemory(temp_obj_name, MAX_BUF);
    ULONG returnedLength;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    if (ResolvedNtQueryObject == nullptr) {
        ResolvedNtQueryObject = (NtQueryObject_proto)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
        if (ResolvedNtQueryObject == nullptr) {
            DBG_LOG("Could not resolve NtQueryObject");
            free(temp_obj_name);
            return NULL;
        }
    }
    status = ResolvedNtQueryObject(hFile, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, temp_obj_name, MAX_BUF, &returnedLength);
    void* obj_name = malloc(MAX_BUF);
    ZeroMemory(obj_name, MAX_BUF);
    // We skip 8 bytes forward to ignore unicode structure
    memcpy(obj_name, ((char*)temp_obj_name + 8), MAX_BUF - 8);
    free(temp_obj_name);
    return (LPWSTR)obj_name;
}
```


### What if a process name exists more than once?
It is possible that a process name exists more than once and we must be able to inject into every instances.
We modify our Process class with a static method that will resolve every instances of the process name.

Inside our injector's main function:
```cpp
// We fetch the processes with our specified process name
DBG_LOG("Waiting for process '%ws'.", wprocess_name.c_str());
std::vector<Process*> processes = Process::get_pids_by_name(wprocess_name, -1);
if (processes.size() > 0) {
    DBG_LOG("We found %d with the name '%ws'", processes.size(), wprocess_name.c_str());
    for (auto process : processes) {
        bool res = false;
        if (process->is_64bit()) {
            DBG_LOG("Injecting in 64bit mode");
            res = process->inject_dll(dll64.c_str());
        }
        else {
            DBG_LOG("Injecting in 32bit mode");
            res = process->inject_dll(dll32.c_str());
        }
        DBG_LOG("Injection result: %s", (res ? "Success" : "Failure"));
    }
}
else {
    DBG_LOG("We couldn't find any process with the name '%ws'", wprocess_name.c_str());
}
```

Our new method inside the Process class:
```cpp
    /// <summary>
    /// Resolves processes with a given name within a certain timeout.
    /// </summary>
    /// <param name="name">Name of the processes to fetch</param>
    /// <param name="timeout">Timeout in milliseconds before aborting, can be -1 to wait undefinitely</param>
    /// <returns>A vector of heap allocated processes instances</returns>
    static std::vector<Process*> get_pids_by_name(std::wstring name, int timeout=-1);
```

Its definition:
```cpp
std::vector<Process*> Process::get_pids_by_name(std::wstring name, int timeout) {
    int elapsed = 0;
    auto start_time = std::chrono::steady_clock::now();
    std::vector<Process*> processes;
    while (timeout == -1 || elapsed < timeout) {
        // Look for process by name
        HANDLE snapshot;
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        // Gets a snapshot of the entire system (https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // No processes running. This is not normal and might be a permission issue.
        if (!Process32First(snapshot, &pe32)) {
            DBG_LOG("Couldn't fetch processes on the system.\n");
            CloseHandle(snapshot);
            return processes;
        }
        do {
            if (!wcscmp(pe32.szExeFile, name.c_str())) {
                // We found our process, we save its informations such as process id and architecture
                DBG_LOG("Found process %ws with PID %d", pe32.szExeFile, pe32.th32ProcessID);
                DWORD pid = pe32.th32ProcessID;
                BOOL is_wow64 = false;
                HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pe32.th32ProcessID);
                IsWow64Process(process_handle, &is_wow64);
                CloseHandle(process_handle);
                bool is_64bit = is_wow64 == false; // wow64 = 32bit emulator
                Process* p = new Process(name, pid, is_64bit);
                processes.push_back(p);
            }
        } while (Process32Next(snapshot, &pe32));

        CloseHandle(snapshot);
        // If we found something then we can return
        if (processes.size() > 0) {
            return processes;
        }
        
        // Update timer
        Sleep(25);
        auto current_time = std::chrono::steady_clock::now();
        elapsed = std::round(std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count());
    }
    DBG_LOG("Couldn't find the process within the time allocation.");
    return processes;
}
```

We can now inject into every instances of a process given its name.


## The 32-bit stack bug

While testing on 32 bit applications, I've encountered a fatal bug that didn't give me much clues as to what was happening.

![bug](/images/fs_capture/32err.png)

After a lengthy debugging session, I finally found what was causing this error. 
The culprit is the call convention which I did not take into account while building my payload in 32-bit. 

The call convention is part of the [ABI](https://en.wikipedia.org/wiki/Application_binary_interface). 

On 32-bit the standard call convention for microsoft apis is stdcall. 

The fix is rather simple, we change the call convention for the 32-bit configuration payload to stdcall:

![bug](/images/fs_capture/errfix32.png)

After applying this change and rebuilding my payload for 32-bit, the application worked flawlessly.













































{{< rawhtml >}}
<div style="margin-bottom: 16rem;margin-top: 16rem;"></div>
{{< /rawhtml >}}