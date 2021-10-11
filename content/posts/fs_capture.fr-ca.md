+++
author = "Kevin Goyette"
title = "Monitorer les accès au système de fichiers en utilisant des hooks sur Windows"
date = "2021-09-10"
description = ""
+++


# Le projet
Cette application ciblera les applications natives et y injectera un payload qui appliquera ensuite un hook toutes les fonctions du système de fichiers.
Pour ce faire, cette application devra être écrite en C ou C++.

# Qu'est-ce qu'un hook?
Un programme import des fonctions de différentes bibliothèques. Disons que nous écrivons une application Windows qui lit un fichier et affiche son contenu.
Nous devons appeler une fonction pour lire ce fichier, puis une autre fonction pour lire son contenu ainsi qu'une fonction pour l'afficher.
Ces fonctions sont déjà implémentées pour nous par Microsoft, il suffit de les importer et de les appeler.

Les programmes conserveront les informations sur ses fonctions importées dans ce qu'on appelle une **Table d'adresses d'importation**, IAT en anglais.
Cette table d'importation est conservée dans l'en-tête Portable Executable (en-tête PE32).

Prenons l'application Windows native *notepad.exe*. Nous pouvons utiliser CFF Explorer pour lire sa table d'adresses d'importation.

![cff](/images/fs_capture/cff_notepad.png)

Pendant l'exécution, le Bloc-notes importera Kernel32.dll, résoudra les adresses des fonctions et les stockera dans sa table d'importation.
Voici à quoi ressemblerait la table d'importation pour Kernel32.dll en mémoire:

| Nom de la fonction  | Adresse en mémoire |
|---------------------|--------------------|
| OpenFile            | 0x1234             |
| ReadFile            | 0x5678             |


 

Un hook consiste à injecter le processus ciblé, en l'occurrence le bloc-notes, et à écraser les adresses à 
l'intérieur de la table d'importation par nos propres adresses.

| Nom de la fonction  | Adresse en mémoire |
|---------------------|--------------------|
| OpenFile            | 0xA000             |
| ReadFile            | 0xB000             |

 

# Configurer le projet
On crée une solution contenant 3 projets. L'injecteur, le payload et un assistant de processus.

## À propos: L'injecteur(64-bit)
L'application d'injection est une application console ou GUI qui effectuera les opérations suivantes:
1. Demander à l'utilisateur un processus cible à injecter
2. Trouver le processus cible
3. Déterminer à partir de l'architecture du processus si le processus est 32 bits ou 64 bits
4. Injecter notre payload dans le processus cible en utilisant la bonne architecture
5. Créer un thread distant sur le processus cible qui exécutera notre payload à l'intérieur du processus cible
6. Quitter puisque le payload s'exécute maintenant dans notre processus cible


## À propos: Le payload(32-bit et 64-bit)
Le payload est une bibliothèque de liens dynamiques(DLL) qui, lorsqu'elle est attachée à un processus,
trouvera la table d'importation et écrasera les fonctions prédéfinies avec ses propres fonctions.
Il placera un hook sur les fonctions API du système de fichiers avec ses propres fonctions. 
Ses propres fonctions enregistreront l'accès aux fichiers et appeleront leur fonction d'origine.

Voici un exemple d'une fonction hook:
```c
// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
HANDLE CreateFileW_hook(LPCWSTR Filename, DWORD DesiredAccess, DWORD ShareMode, LPSECURITY_ATTRIBUTES SecAttribs, DWORD CreationDisp, DWORD Flags, HANDLE Template) {
    // On appele la fonction originale pour obtenir son résultat
    HANDLE handle = original_CreateFileW(Filename, DesiredAccess, ShareMode, SecAttribs, CreationDisp, Flags, Template);
    // On affiche l'accès au fichier et son résultat
    DBG_LOG("[CALL]: Creating/Opening file %ws with handle %p", Filename, handle);
    // On retourne la valeur attendue
    return handle;
}
```

Comme nous pouvons le voir, le processus cible ne verra aucun changement lors de l'appel de CreateFileW puisque nous gardons le comportement d'origine intact.
Nous ajoutons simplement une fonction de journalisation(DBG_LOG) lors de l'appel de fonction.

## À propos: L'assistant de processus(32-bit)
Windows loads different internal libraries into memory such as Kernel32.dll. These libraries are available system-wide.
This means if a program imports a function from Kernel32, its address would be valid for any other program on the system. 
There is a catch however, Kernel32 is loaded twice in memory. 

Windows charge différentes bibliothèques internes en mémoire telles que Kernel32.dll. Ces bibliothèques sont disponibles sur tout le système.
Cela signifie que si un programme importe une fonction de Kernel32, son adresse sera valide pour tout autre programme du système.
Il y a un hic cependant, Kernel32 est chargé deux fois en mémoire.

1. La première instance est `"C:\Windows\System32\kernel32.dll"` qui est la variante 64-bit.
2. L'autre instance est `"C:\Windows\SysWOW64\kernel32.dll"` qui est la variante 32-bit qui est chargée 
sur le sous-système WOW64 qui s'occupe d'exécuter les application 32-bit sur un système 64-bit.

 

# Implémenter un payload test
Avant de commencer à implémenter l'injecteur, nous avons besoin d'un moyen de savoir si notre payload a été injecté avec succès dans le 
processus et de nous assurer que son point d'entrée est exécuté.

Pour ce faire, nous faisons en sorte que notre payload crée un thread dans lequel il affiche une ligne de débogage 
à l'intérieur du débogueur système. Nous pouvons lire la sortie de débogage en utilisant WinDbg ou bien DebugView++.

```cpp
#include <cstdio>

// Un macro permettant d'afficher du texte dans le débogueur système
#define MAX_BUF 512
#define DBG_LOG(fmt, ...) {\
    char buf[MAX_BUF]={0}; \
    sprintf_s(buf, MAX_BUF, "[fs_monitorer][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(buf);\
}

// Point d'entrée du payload
BOOL APIENTRY DllMain(HMODULE module, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DBG_LOG("Injected");
        break;
    }
    return TRUE;
}
```

Notre payload test est maintenant prêt. On peut commencer à travailler sur l'injecteur.

# Implémenter l'injecter
Nous commençons par créer une classe nommée Process. Cette classe agira comme contrôleure pour les opérations de processus Windows.
Un processus a un nom, une architecture (32 bits ou 64 bits) et un identifiant de processus. On se retrouve avec la classe suivante :

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
    /// Attend que le processus soit trouvé afin d'y assigner son identifiant
    /// </summary>
    /// <param name="timeout">Temps d'attente en milisecondes avant d'abandonner. -1 pour attendre indéfiniement</param>
    /// <returns>L'identifiant du processus</returns>
    DWORD wait_for_process(int timeout = -1);

    /// <summary>
    /// Obtient l'adresse de LoadLibraryA en fonction de l'architecture du processus cible
    /// </summary>
    /// <returns>L'adresse de LoadLibraryA.</returns>
    FARPROC get_LoadLibraryA_address();

    /// <summary>
    /// Injecte un dll dans le processus cible
    /// </summary>
    /// <param name="dll_path">Le chemin complet du dll à injecter</param>
    /// <returns>Retourne un booléen vrai si l'injection a réussie ou non</returns>
    bool inject_dll(const char* dll_path);
    bool is_64bit() { return this->m_is_64bit; }
};
```

La méthode `wait_for_process` est simple à implémenter étant donné qu'elle utilise les fonctions de l'api de windows
pour trouver le processus par son nom et retourne son identifiant donc je vais passé à la prochaine étape.

Je veux plutôt élaborer sur les méthodes `get_LoadLibraryA_address` et `inject_dll`.

La méthode `get_LoadLibraryA_address`  est assez simple si le processus est 64-bit cependant dans le cas contraire
le processus 32-bit ne pourra pas utiliser notre adresse 64-bit donc on doit trouver l'adresse de LoadLibraryA 
provenant du sous-système WOW64.

C'est donc ici que l'on appelle notre assistant de processus qui est un programme 32-bit qui retourne 
l'adresse de LoadLibraryA provenant du sous-système WOW64.

```cpp
FARPROC Process::get_LoadLibraryA_address() {
    assert(this->id >= 0);
    // Si le processus cible est 64-bit alors on retourne tout simple l'adresse de LoadLibraryA.
    if (this->m_is_64bit) {
        return GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    }

    // Le processus est 32-bit donc on doit appeller notre assistant de processus pour obtenir l'adresse 32-bit

    // On obtient le chemin courant de notre application pour localiser ProcessHelper32
    char working_dir[MAX_BUF] = { 0 };
    if (!GetCurrentDirectoryA(MAX_BUF-1, working_dir)) {
        DBG_LOG("[ERROR]: Could not retrieve current working directory while resolving LoadLibraryA. Aborting...\n");
        return NULL;
    }
    
    // On crée un nouveau processus pour ProcessHelper32
    std::string exe_path = std::string(working_dir) + "\\ProcessHelper32.exe";
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    ZeroMemory(&process_info, sizeof(process_info));
    BOOL process_created = CreateProcessA(exe_path.c_str(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, &startup_info, &process_info);
    if (process_created) {
        // On attend que le processus termine
        WaitForSingleObject(process_info.hProcess, INFINITE);
        DWORD process_return = 0;
        BOOL res = GetExitCodeProcess(process_info.hProcess, &process_return);
        if (!res) {
            DBG_LOG("Error while getting process returned value: %d\n", GetLastError());
        }
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);

        // On retourne l'adresse retournée par ProcessHelper32
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
La méthode d'injection écrit le chemin complet de notre payload(dll) à l'intérieur de la mémoire du processus cible.
Par la suite, elle crée un thread à l'intérieur du processus cible en utilisant l'adresse de LoadLibraryA comme point d'entrée.

Ceci aura pour résultat que le processus cible exécute le code suivant: `LoadLibraryA(dll_path)`

```cpp
bool Process::inject_dll(const char* dll_path) {
    assert(this->id >= 0);
    DBG_LOG("Injecting %s on pid %d\n", dll_path, this->id);
    // On ouvre une porte vers le processus cible
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, this->id);
    SIZE_T written_bytes = 0;
    // On trouve l'adresse de LoadLibraryA
    PTHREAD_START_ROUTINE loadlibrary_address = (PTHREAD_START_ROUTINE)this->get_LoadLibraryA_address();
    if (loadlibrary_address <= 0) {
        DBG_LOG("Address of LoadLibraryA is invalid. Addr: %p\n", loadlibrary_address);
        return false;
    }
    // On écrit le chemin complet du dll à l'intérieur du processus cible (+1 pour octet null)
    LPVOID dllpath_address = VirtualAllocEx(process_handle, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(process_handle, dllpath_address, dll_path, strlen(dll_path) + 1, &written_bytes);
    // On crée un thread à l'intérieur du processus cible qui exécute 
    // notre payload injecté(stack size = 1024 octets, n'est pas important dans notre cas)
    CreateRemoteThread(process_handle, NULL, 1024, loadlibrary_address, dllpath_address, 0, 0);
    return true;
}
```
---

 

## On déclenche l'antivirus!

![virus_achv](/images/fs_capture/virus_achv.png)

![virus_achv](/images/fs_capture/virus.png)

Microsoft Windows Defender n'est pas content à propos du comportement de notre application bien évidemment.

J'ai donc ajouté le chemin du projet à la liste des exclusions de Defender.


 

# Implémenter l'assistant de processus
L'assistant de processus est assez simple à implémenter. On fait tout simplement importer LoadLibraryA et 
on retourne son adresse. Étant donnée que l'assistant est une application 32-bit alors l'adresse de 
LoadLibraryA est 32-bit aussi.

```cpp
#include <cstdio>
#include <windows.h>

int main(int argc, char** argv){
    DWORD addr = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    printf("Found Kernel32.LoadLibraryA at %p\n", addr);
    return addr;
}

```



# Tester l'injecteur
On peut maintenant tester notre injecteur sur n'importe quelle application 64-bit.
Je vais prendre notepad.exe comme ~~victime~~ exemple.

On exécute l'injecteur et on spécifie Notepad.exe comme étant le processus cible.
On ouvre ensuite WinDbg, dans mon cas je vais utiliser [DebugView++](https://github.com/CobaltFusion/DebugViewPP)
qui me permet de filtrer à travers le journal de débogage plus facilement.

Voici ce qu'on obtient dans notre console:
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

Mais plus important encore, voici la sortie DebugView++:
```
1   3.104851    6096    Notepad.exe [fs_monitorer][DllMain] Injected
```

Ceci signifie donc que notre payload a été injecté correctement et son code a été exécuté. 
On peut donc conclure que notre l'injecteur fonctionne, du moins pour 64-bit.

On peut aussi tester sur une application 32-bit, il y a une application 32-bit de windows ici: `C:\Windows\SysWOW64\nslookup.exe`.

On exécute notre test sur `nslookup.exe`:
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

Sortie de DebugView++
```
1   114.787226  18376   nslookup.exe    [fs_monitorer][DllMain] Injected
```
---

Les fondations de notre application fonctionnent. On peut maintenant commencer à travailler sur
le processus de hooking dans notre payload.

 



# Implémenter le payload

 

### La fonction de hook IAT
Cette section est assez lourde. Nous commençons par la fonction de hook IAT.
La fonction de hook IAT est basée sur les pages de documentation Microsoft suivantes:
* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#delay-load-import-tables-image-only
* https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2

Pour plus de documentation, j'ai dû lire les fichiers d'en-tête Windows, principalement `winnt.h` , 
à l'intérieur de Visual Studio pour mieux comprendre leurs structures de données.

Notre fonction de hook IAT prend le nom de la fonction qui reçoit le hook 
ainsi que l'adresse de sa fonction hook (notre propre fonction).

La fonction retourne ensuite l'adresse de la fonction originale.

Voici la fonction de hook IAT:

```cpp
// Cette valeur est utilisée durant le processus de hook IAT afin de s'assurer que les adresse sont valides
#if _WIN64
    #define INVALID_ORDINAL 0x8000000000000000
#else
    #define INVALID_ORDINAL 0x80000000
#endif

/// <summary>
/// Détourne une fonctione vers une autre fonction
/// </summary>
/// <param name="function_name">Nom de la fonction à détourner.</param>
/// <param name="addr_new_fn">Adresse de la nouvelle fonction</param>
/// <returns>Retourne l'adresse de la fonction originale ou NULL si on ne peut pas trouver la fonction recherchée</returns>
DWORD_PTR hook_IAT(std::string function_name, void* addr_new_fn) {
    // Obtient l'adresse du module courant
    LPVOID image_base = GetModuleHandleA(NULL);
    if (image_base == NULL) {
        DBG_LOG("[ERROR]: Image base is null");
        return NULL;
    }
    // Lit l'en-tête de l'image
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
    PIMAGE_DOS_HEADER dos_headers = (PIMAGE_DOS_HEADER)image_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_base + dos_headers->e_lfanew);
    // Obtient le imports descriptor
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = NULL;
    IMAGE_DATA_DIRECTORY imports_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imports_directory.VirtualAddress + (DWORD_PTR)image_base);
    // On passe à travers chaque descriptor(module) et on obtient leur table d'importation
    while (import_descriptor->Name != NULL) {
        // On charge le module courant pour obtenir sa table d'importation
        LPCSTR library_name = (LPCSTR)import_descriptor->Name + (DWORD_PTR)image_base;
        HMODULE library = LoadLibraryA(library_name);
        DBG_LOG("Processing module %s", library_name);
        if (library) {
            // On lit la table d'importation du module courant
            PIMAGE_THUNK_DATA orig_first_thunk = NULL, first_thunk = NULL;
            orig_first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)image_base + import_descriptor->OriginalFirstThunk);
            first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)image_base + import_descriptor->FirstThunk);
            while (orig_first_thunk->u1.AddressOfData != NULL) {
                PIMAGE_IMPORT_BY_NAME function_import = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)image_base + orig_first_thunk->u1.AddressOfData);
                // On doit faire attention à l'adresse et s'assurer qu'elle est valide
                if (orig_first_thunk->u1.AddressOfData <= INVALID_ORDINAL) {
                    DBG_LOG("\tFound function: %s", function_import->Name);
                }
                // On vérifie que l'adresse est valide car certaines fonctions importées n'ont pas d'adresse définies ici
                if (orig_first_thunk->u1.AddressOfData <= INVALID_ORDINAL && std::string(function_import->Name).compare(function_name) == 0) {
                    // On change la protection mémoire de la table d'importation afin de pouvoir la modifier
                    DWORD old_protection = 0, void_protect = 0;
                    VirtualProtect((LPVOID)(&first_thunk->u1.Function), 8, PAGE_READWRITE, &old_protection);
                    // On sauvegarde l'adresse de la fonction originale
                    DWORD_PTR original_address = first_thunk->u1.Function;
                    // On hook la fonction
                    first_thunk->u1.Function = (DWORD_PTR)addr_new_fn;
                    // On restaure la protection mémoire de la table d'importation
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


### Notre premier hook
Au début de ce post, on a ouvert notepad.exe à l'intérieur de CFF Explorer pour voir sa table d'importation: 

![cff](/images/fs_capture/cff_notepad.png)

 

CreateFileW semble être un bon candidat pour notre premier hook. On copie donc sa signature 
en se fiant à la documentation fournie par Microsoft:

https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew


Le code suivant contient le prototype de définition pour CreateFileW, une variable globale pour sauvegarder son
adresse originale et la fonction de hook.

```cpp
// Définition pour le prototype de CreateFileW 
typedef HANDLE(*proto_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

// Variable globale pour sauvegarder l'adresse originale de CreateFileW
proto_CreateFileW original_CreateFileW = nullptr;

// Fonction hook pour CreateFileW avec affichage du nom de fichier
HANDLE CreateFileW_hook(LPCWSTR filename, DWORD des_acces, DWORD shr_mode, LPSECURITY_ATTRIBUTES sec_atr, DWORD creation, DWORD flags, HANDLE htemplate) {
    // On appelle la fonction originale pour obtenir son résultat
    HANDLE handle = original_CreateFileW(filename, des_acces, shr_mode, sec_atr, creation, flags, htemplate);
    // On affiche le nom du fichier
    DBG_LOG("[CALL]: Creating/Opening file %ws with handle %p", filename, handle);
    // On retourne le résultat de la fonction originale
    return handle;
}

/// <summary>
/// Affiche le résultat d'un hook
/// </summary>
/// <param name="function_name">Le nom de la fonction que l'on a essayé de hook.</param>
/// <param name="old_addr">L'adresse originale retournée par hook_IAT.</param>
void dbgPrintHookStatus(std::string function_name, void* old_addr) {
    if (old_addr != NULL) {
        DBG_LOG("[LOG]: Hooked %s, old address: %p", function_name.c_str(), old_addr);
    }
    else {
        DBG_LOG("[ERROR]: Failed to hook %s", function_name.c_str());
    }
}

// Thread principal pour placer nos hook iat sur nos fonctions cibles. Le thread se termine après avoir 
// completer les hooks.
DWORD WINAPI main_thread(void*) {
    // On hook et on sauvegarde l'adresse originale à l'intérieur de notre variable globale
    original_CreateFileW = (proto_CreateFileW)hook_IAT("CreateFileW", CreateFileW_hook);
    // On affiche le résultat de notre fonction de hook iat
    dbgPrintHookStatus("CreateFileW", (void*)original_CreateFileW);
    return TRUE;
}

// Entrée principale 
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

### Tester notre premier hook
On exécute notre injecteur, on spécifie le processus cible et on jette un coup d'oeil à l'intérieur de DebugView++:
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

Il semble que notre payload a placer son hook sur `CreateFileW` 
mais on doit s'assurer que la fonction est détournée correctement.

On ouvre donc un fichier avec Bloc-notes et on vérifie que l'information soit transmise dans notre débogueur:

```
[fs_monitorer][CreateFileW_hook] [CALL]: Creating/Opening file C:\Users\kevin\Desktop\projects\fs_monitorer\test.txt with handle 0000000000000484
```

Notre hook fonctionne! Il affiche le nom du fichier ouvert par bloc-notes.
On peut donc placer un hook sur n'importe quelle fonction importée par n'importe quel programme.

### Falsification de fichier pour CreateFileW
Notre hook affiche tout simplement le nom du fichier par contre il est possible qu'on change le comportement de la fonction.

Admettons que nous avons 2 fichiers sur notre système:
1. Un fichier nommé `secret.txt` qui contient le texte `SECRET123`.
2. Un fichier nommé `fake_secret.txt` qui contient le texte `NOT_A_SECRET`.

On change notre fonction hook pour bloquer l'accès à secret.txt et on le remplace par fake_secret.txt.


```cpp
HANDLE CreateFileW_hook(LPCWSTR filename, DWORD des_acces, DWORD shr_mode, LPSECURITY_ATTRIBUTES sec_atr, DWORD creation, DWORD flags, HANDLE htemplate) {
    HANDLE handle = NULL;
    const LPCWSTR secret_file = L"C:\\Users\\kevin\\Desktop\\projects\\fs_monitorer\\secret.txt";
    const LPCWSTR fake_file = L"C:\\Users\\kevin\\Desktop\\projects\\fs_monitorer\\fake_secret.txt";
    // On vérifie si le fichier ouvert est notre fichier secret
    if (lstrcmpiW(filename, secret_file) == 0) {
        // On lui donne notre faux fichier à la place
        handle = original_CreateFileW(fake_file, des_acces, shr_mode, sec_atr, creation, flags, htemplate);
    }
    else {
        // On appelle notre fonction originale sinon
        handle = original_CreateFileW(filename, des_acces, shr_mode, sec_atr, creation, flags, htemplate);
    }   
    // On affiche le nom du fichier ouvert
    DBG_LOG("[CALL]: Creating/Opening file %ws with handle %p", filename, handle);
    // On retourne le résultat de la fonction originale
    return handle;
}
```

Nous réinjectons maintenant dans le bloc-notes et ouvrons notre fichier secret.
Le résultat attendu dans le bloc-notes est `SECRET123` mais puisque nous avons redirigé
le fichier vers notre faux fichier secret, nous obtenons le résultat suivant:

![secret](/images/fs_capture/secret.png)


Bloc-notes pense qu'il a ouvert `secret.txt` alors qu'en fait c'est bel et bien `fake_secret.txt` qui est ouvert. 

Nos hooks peuvent donc non seulement afficher de l'information sur une fonction mais en plus 
changer son comportement.

On revient à notre hook qui ne fait qu'afficher le nom du ficiher étant donné que le but du 
projet est tout simplement d'afficher des traces sur les fichiers ouverts.

On peut maintenant trouver d'autres fonctions qui manipule les fichiers afin qu'on
puisse placer un hook sur ces fonctions.

 

### Placer un hook sur d'autres fonctions de l'api d'accès aux fichiers
Nous pouvons maintenant palcer un hook sur d'autres fonctions API du système de fichiers en utilisant le même concept.
Le seul problème est lorsque nous gérons les [tubes nommés](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes).
Notre fonction a un handle mais pas d'informations dessus, j'ai donc dû écrire une fonction pour obtenir le nom du tube.
C'était un peu plus compliqué car il n'y a pas de documentation officielle sur le sujet par Microsoft.
J'ai dû obtenir ma documentation sur [ntinternals.net](http://undocumented.ntinternals.net/index.html).

Le code suivant décrit comment j'ai réussi à obtenir le nom d'un tube nommé en utilisant son handle.
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

/* API non-documentée: 
http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FOBJECT_INFORMATION_CLASS.html 
*/
#define ObjectNameInformation 1

/// <summary>
/// Obtient le nom d'un tube 
/// </summary>
/// <param name="hFile">Handle du tube/fichier</param>
/// <returns>Le nom du tube alloué sur le tas</returns>
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
    // On ignore les 8 permiers octets pour ignorer la structure unicode
    memcpy(obj_name, ((char*)temp_obj_name + 8), MAX_BUF - 8);
    free(temp_obj_name);
    return (LPWSTR)obj_name;
}
```


### Que faire si le nom d'un processus revient plusieurs fois?
Il est possible que le nom d'un processur revienne plusieurs fois et l'on veut être capable d'injecter toutes les instances
portant le nom cible.

On modifie notre classe Process pour y ajouter une méthode statique qui trouvera toutes les instances portant le nom cible.

À l'intérieur de notre injecteur
```cpp
// On trouve tous les processus ayant le nom cible
DBG_LOG("Waiting for process '%ws'.", wprocess_name.c_str());
std::vector<Process*> processes = Process::get_pids_by_name(wprocess_name, -1);
if (processes.size() > 0) {
    DBG_LOG("We found %d with the name '%ws'", processes.size(), wprocess_name.c_str());
    // On injecte tous les processus trouvés
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

Notre nouvelle méthode à l'intérieur de notre classe Processus
```cpp
    /// <summary>
    /// Trouve des processus portant le nom cible ou abandonne après un certain délais
    /// </summary>
    /// <param name="name">Nom du processus cible</param>
    /// <param name="timeout">Temps d'attente en millisecondes avant d'abandonner, peut être -1 pour attendre indéfiniement</param>
    /// <returns>Un vecteur d'instance de processus allouées sur le tas</returns>
    static std::vector<Process*> get_pids_by_name(std::wstring name, int timeout=-1);
```

Implémentation de la nouvelle méthode:
```cpp
std::vector<Process*> Process::get_pids_by_name(std::wstring name, int timeout) {
    int elapsed = 0;
    auto start_time = std::chrono::steady_clock::now();
    std::vector<Process*> processes;
    while (timeout == -1 || elapsed < timeout) {
        // Cheche le processus par son nom
        HANDLE snapshot;
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        // Obtient une capture du système complet (https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // Aucun processus trouvé. Ceci n'est pas normal et pourrait être un problème de permission
        if (!Process32First(snapshot, &pe32)) {
            DBG_LOG("Couldn't fetch processes on the system.\n");
            CloseHandle(snapshot);
            return processes;
        }
        do {
            if (!wcscmp(pe32.szExeFile, name.c_str())) {
                // On a trouvé un processus portant le nom cible. On sauvegarde ses informations
                DBG_LOG("Found process %ws with PID %d", pe32.szExeFile, pe32.th32ProcessID);
                DWORD pid = pe32.th32ProcessID;
                BOOL is_wow64 = false;
                HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pe32.th32ProcessID);
                IsWow64Process(process_handle, &is_wow64);
                CloseHandle(process_handle);
                bool is_64bit = is_wow64 == false; // wow64 = émulateur 32bit 
                Process* p = new Process(name, pid, is_64bit);
                processes.push_back(p);
            }
        } while (Process32Next(snapshot, &pe32));

        CloseHandle(snapshot);
        // Si on a trouvé quelque chose alors on peut retourner
        if (processes.size() > 0) {
            return processes;
        }
        
        // M.A.J. chrono
        Sleep(25);
        auto current_time = std::chrono::steady_clock::now();
        elapsed = std::round(std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count());
    }
    DBG_LOG("Couldn't find the process within the time allocation.");
    return processes;
}
```

On peut maintenant injecter notre payload dans n'importe quel processus portant le nom cible qu'on lui donne.

## Le bug du stack sur 32-bit
Pendant que je testais sur des applications 32-bit, j'ai rencontré un bug étrange qui me donnait pas beaucoup d'indices
à propos de la cause de l'erreur.

![bug](/images/fs_capture/32err.png)

Après une bonne séance de débogage, j'ai finalement trouvé d'où provenanit l'erreur.

Le coupable est la convention d'apppel que je n'ai pas pris en compte lorsque j'ai bâtit le payload
en 32-bit.

La convention d'appel fait partie de l'[ABI](https://en.wikipedia.org/wiki/Application_binary_interface). 

Les applications 32-bit, la convention d'appel pour les apis Microsoft est `stdcall`.

Ce bug est facile à corriger, il suffit de changer la convention d'appel pour la configuration 32-bit du payload:

![bug](/images/fs_capture/errfix32.png)

Après appliquer ce changement pour mon payload 32-bot, l'application fonctionne sans problèmes!













































{{< rawhtml >}}
<div style="margin-bottom: 16rem;margin-top: 16rem;"></div>
{{< /rawhtml >}}