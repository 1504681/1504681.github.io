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


## HashMyFiles

Next we are going to use HashMyFiles to generate a hash to copy the MD5 and check virustotal.
![image](https://user-images.githubusercontent.com/84855585/131649532-c082d722-4c09-4c4c-bff6-022e98cc7278.png)

Hashes are a way to ID the file. Some files can be much to big to upload to virustotal, and for those files we can generate a hash, and just search the hash.

Search the md5 on virustotal
![image](https://user-images.githubusercontent.com/84855585/131649656-5bf87f5d-32de-4a12-8978-c5d2da27b7f8.png)
![image](https://user-images.githubusercontent.com/84855585/131649672-cb7c02a2-d815-4d4a-81ec-c549b257f87e.png)

As we can see here, the file is clearly malicious.





# Dynamic Analysis Workflow

## Sequence

1) Start Procmon -> pause -> clear
2) Start Fakenet
3) Start Regshot, take 1st snapshot
4) Once the first snapshot is completed -> resume procmon
5) Run the malware for 1-3 mins and study the Fakenet output
6) After 3 minutes of malware runtime, pause procmon
7) Use Regshot to take the 2nd snapshot
8) Regshot -> Compare -> Compare and show output
9) Study Regshot output

Procmon filters
ProcessName = malware-name
Operation is {
	WriteFile
	SetDispositionInformationFile
	RegSetValue
	ProcessCreate
	TCP
	UDP
}
add these values one at a time to the process monitor


## Registry Persistence

There are common places that malware will install persistance in the registry.
Some of the common places are:

\Software\Microsoft\Windows\CurrentVersion\Run
\Software\Microsoft\Windows\CurrentVersion\RunOnce
\Software\Microsoft\Windows\CurrentVersion\RunServices
\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs

## DLL Search Order

Directory of Program -> \windows\system32 -> \windows\system -> \windows -> Current Directory -> %PATH% 

Malware might put a dll in the Directory so that it uses that version instead of a DLL found in windows systemfiles. (Because it is earlier in the search order, once the DLL is found, the search is over.)

# Dynamic Analysis of Malware-Sample-1

- Turn on procmon -> pause -> clear
- Start fakenet
- Start Regshot -> take first shot (this will take a few minutes)
- After 1st shot is completed, turn Capture on in Procmon settings
- Start the malware

We first notice in Fakenet that the malware is trying to connect to a webserver at mbaquyahcn.biz:80

![image](https://user-images.githubusercontent.com/84855585/131794482-211c54ff-8e53-4fbb-97df-13dae04a4c9a.png)

trying to post data 

![image](https://user-images.githubusercontent.com/84855585/131794718-07ffeef4-2cc6-4e3e-89c3-6827e01bc72e.png)

- Next we take the 2nd snapshot in Regshot -> Compare 

Now Regshot opens a text file with all the changed Registy values

![image](https://user-images.githubusercontent.com/84855585/131795043-2c12b1f9-672d-47b2-8732-407a9b6a052b.png)


Here we can see the persistence, it adds a RunOnce value for the exe "\Appdata\Roaming\12648430\spollsv.exe"

![image](https://user-images.githubusercontent.com/84855585/131795305-185a3edc-81fd-45dc-a4de-46f6bf1687e7.png)

And here under Files added, we can see the new exe has been added as well.

![image](https://user-images.githubusercontent.com/84855585/131795517-4801af41-4ec1-4a48-b35a-28b3b27595ba.png)

Under files deleted, we can see that during execution, the malware deleted itself.

![image](https://user-images.githubusercontent.com/84855585/131795571-70f3397b-6a4f-4ca9-a048-946bf98bb3ee.png)








