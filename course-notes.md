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

## Malware1(budget-report.exe) -> put into TridNET

TridNET shows us very likely -> file is an exe
![image](https://user-images.githubusercontent.com/84855585/131647059-d6041f21-fa6f-4153-9b58-9cba293b2035.png)
	
## Drag Malware1 into PEstudio

This file has many indicators that it is a malicious file, the file is scored by virustotal, the file exposes TSL callbacks, the file imports symbol(s), the amount of imports is suspicious.

![image](https://user-images.githubusercontent.com/84855585/131647409-bf431b8f-45d2-45b7-9a2b-3d0a5ebb6b89.png)

### Strings

PEStudio shows us in the blacklisted strings, that we can see RegDeleteValue, RegSetValueEx, these are to give the malware persistence.

![image](https://user-images.githubusercontent.com/84855585/131647971-9beb7ba2-a5b7-459e-b707-cef60009025d.png)

Also we can notice there are plenty of networking strings like "connect, socket, gethostbyname" APIs that connect to the network.
![image](https://user-images.githubusercontent.com/84855585/131648312-715ae5b6-7dcc-4117-af1d-f2ab6c624c18.png)

### Imports

In the imports section, we find plenty of Registry imports for this malware to create & delete registry values.

![image](https://user-images.githubusercontent.com/84855585/131648692-03b54208-a0e2-45a7-b4e4-e7d2408e4415.png)

Also in the imports we find CreateToolhelp32Snapshot, Process32First & Process32Next. Malware can use these APIs to enumerate through the process list looking for tools such as wireshark, x64dbg, procmon etc, to help prevent analysis.







