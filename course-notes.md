# Software Debugging Course Notes
https://crackinglessons.com/learn/
CSL Notes
Started taking notes @ Defeating Software Protection Module
### Packed Software

Packing = Small Size
Protecting = Anti Debugging


Packing = Prevent Reversing

Unpacking = Let it uncompress into memory -> extract exe into new exe

Loaders/ Runtime Patching = Patch the process in memory instead of patching the file.

unpacker code = stub


Look for PUSHAD or PUSH EBP
-> put a hardware breakpoint on the EBP address in the stack
-> f9 to continue and break after POPAD or ON POP EBP
-> trace with f7 and when you encounter a JMP
-> JMP will jump to OEP of original program
-> at OEP use scylla plugin to dump the whole program
-> fix the IAT

IAT is a TABLE listing the MEMORY ADDRESS of the DLLs which the program NEEDS in order to RUN



### Execution of Packed EXE Program

Starts from new OEP (EntryPoint)

Saves the REGISTER STATUS using PUSHAD or PUSH EBP instruction

all the PACKED SECTIONS are UNPACKED in memory

RESOLVE the import address table IAT of the ORIGINAL EXE

RESTORE the original REGISTER STATUS using POPAD or POP EBP instruction

JUMP to OEP to begin execution

#unpacking 101
Basically

Find the unpacked exe in memory with scylla

dump it

#Fixing the IAT table

use syclla to IAT autosearch -> click no
get imports
fix dump -> dump.exe


### Loaders

Create a loader with dup2

Patch the file -> file -> patch file -> EXPORT

### Anti-AntiDebug

command "bp IsDebuggerPresent"

Detect it easy will show you what proctections the program has


### Packing & Anti-Debug Combo

CompareStringW 
If the strings are the same it sets EAX to 2

Either way it always subtracts 2 
-> test if eax now equals zero


### Keygens

self keygen -> wherever it moves the string "wrong serial key" into edx for example
			-> in assembly, replace that instruction to move the serial key into edx


### Assembly

Flat Assembler (FASM)

hello db 'hello world',0dh,0ah,0
odh = carriage return
0ah = line feed
carriage return + line feed = new line
0 = null terminator

add esp, 4  ; clean the stack


# Malware Analysis Course Notes
https://www.udemy.com/course/malware-analysis-fundamentals

## Win32 Api

NT APIs in ntdll.dll are not officially documented -> find them at http://undocumented.ntinternals.net

NtCreateSection is an undocumented API usually used by malware for *Process Hollowing*

Process Hollowing
  - Legitimate process is loaded on the system to act as a *container* for malicious code.
  - Legit code is deallocated and replaced
  - Helps process hide amongst normal processes

APIs that perform Registry Operations
  - RegCreateKey
  - RegDeleteKey
  - RegSetValue

APIs for virtual memory
  - VirtualAlloc
  - VirtualProtect
  - NtCreateSection
  - WriteProcessMemory
  - NtMapViewOfSection
  
 ## Behaviour Identification with APIs
 
 Just because these APIs are in use =/= software is malicious.
 	- Context Matters
	- What are the parameters?
	- Sets of APIs used in sequence
	
Example 1) Process Hollowing
	CreateProcessA API to make new process in suspended mode
	sets dwCreationFlag parameter to CREATE_SUSPENDED
	This is a red flag because normal programs do not do this
Example 2) WriteProcessMemory
	Writes into memory of another process
	Debuggers use this so by itself - not malicious
	If also using VirtualAllocEx & CreateRemoteThread -> likely malware
	
	This is suspicious because of the Sequence the APIs are in
	
### Using Handle to Identify Sequences

Handle is a reference to files, registry, memory, and processes
Processes use handles to do operations on the referred object
Tracking handles -> identify sequence of APIs

# Static and Dynamic Analysis

Malware analysis process
obtain malware -> static/dynamic analysis -> reporting

Static Analysis -> analysis without execution
(hashing, embedded strings, PE header)

Dynamic analysis -> analysis with execution
(monitoring changes, behavior monitoring)

Snapshot clean system -> Execute Malware -> Take Snapshot
Compare two snapshots

## Dynamic Analysis tools
Regshot - registry snapshot
Autoruns - check for persistance
Fakenet - capture network traffic to other servers
Wireshark - 
Procmon
Procdot


# Static Analysis of Malware-Sample-1

Malware1(budget-report.exe) -> put into TridNET
	-> file is an exe
	![image](https://user-images.githubusercontent.com/84855585/131647059-d6041f21-fa6f-4153-9b58-9cba293b2035.png)


