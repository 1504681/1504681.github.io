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

Back under procmon, we have way too many results currently loaded. We can filter the results for the following:
	Process Name is = [exe name]
	Operation is = WriteFile
	Operation is = SetDispositionInformationFile
	Operation is = RegSetValue
	Operation is = Process Create
	Operation is = TCP
	Operation is = UDP
	
![image](https://user-images.githubusercontent.com/84855585/131803591-32d6568d-3123-4d4f-be40-a18c1d5661ac.png)

This is great, now we're only showing these specific results, and we're down to 542 events out of the 667,750 events that happened during the time procmon was active.

![image](https://user-images.githubusercontent.com/84855585/131803731-2d84493f-e213-46a2-8f1d-1990b8f677a9.png)

Now we're going to save ALL EVENTS as a logfile.mml

![image](https://user-images.githubusercontent.com/84855585/131804006-0fc2695e-d662-4b13-81f2-5b07280677e3.png)


After that, we're going to save only the current filter results as a .CSV format file (for analysis in Procdot)

![image](https://user-images.githubusercontent.com/84855585/131804094-a648e5c7-2493-40f6-8bba-44cab185e42d.png)

We're going to launch ProcDOT, and import the .CSV file we just generated. This will give us a graph visualization of the results.

![image](https://user-images.githubusercontent.com/84855585/131804669-4af29c00-39dd-41cd-ac6f-d1ea93d2b938.png)

![image](https://user-images.githubusercontent.com/84855585/131804683-41c90291-85ca-49fc-b77a-193bbda8db4a.png)

![image](https://user-images.githubusercontent.com/84855585/131804881-d02433bb-fdfb-4a7f-9bb1-73f0f7525e79.png)

We can see some persistence keys

![image](https://user-images.githubusercontent.com/84855585/131804968-7b126a9b-d979-4da2-a4d2-a4848f450333.png)

![image](https://user-images.githubusercontent.com/84855585/131804985-a46aa3e8-503d-4de4-ad74-1b139a80b4da.png)

These components are known as *Artifacts*.

# Network Analysis of Malware-Sample-1

![image](https://user-images.githubusercontent.com/84855585/132088773-ebb830e9-b699-46c8-8897-249a95113029.png)

Fakenet has already given us enough info to know that the malware is trying to make a HTTP POST request to a webserver at mbaquyahcn.biz:80 

![image](https://user-images.githubusercontent.com/84855585/132088837-4982291a-d4db-483e-8d93-011567d1fc39.png)


With 938 bytes of information.

![image](https://user-images.githubusercontent.com/84855585/132088840-b0640d35-d99a-4d14-b294-b364fd7bd9e3.png)

Next step we take the .pcap file thats in our Fakenet logs folder, for analysis in Wireshark.

![image](https://user-images.githubusercontent.com/84855585/132088860-3b285f42-c593-4ba0-87d9-426bfc79f6fa.png)

![image](https://user-images.githubusercontent.com/84855585/132089096-aa55eb26-91f5-4e30-9142-9dbe87d2e169.png)


Now we're going to filter for HTTP

![image](https://user-images.githubusercontent.com/84855585/132089105-e4db93e8-123d-429b-ab87-2101d3009ead.png)

Now we can follow the TCP stream for the POST request

![image](https://user-images.githubusercontent.com/84855585/132089140-d29e16f7-9145-47ad-960d-8dd82ef6f98d.png)

Here we can see the request we saw earlier, with the encrypted data. Also we can see Fakenet's response in blue at the bottom.

![image](https://user-images.githubusercontent.com/84855585/132089171-c8167d74-2a37-4a23-814c-9a7033610a01.png)

Now that we're finished -> restore to previous VM snapshot.

# Lab Exercise, Analysis of Malware-Sample-2 (financials-xls.exe)

For this Lab Exercise, we recieved the file "financials-xls.exe"

![image](https://user-images.githubusercontent.com/84855585/132089487-6bc00e44-bc4e-432d-8b1a-8de6fac99648.png)

When we take the program into DetectItEasy, it detects that the file is Packed with UPX. So we will use the command "upx -d -o 
financials-xls-unpacked.exe financials-xls.exe"

![image](https://user-images.githubusercontent.com/84855585/132089563-5ef8d450-e510-499d-ba59-5f2f86cb1fe5.png)

![image](https://user-images.githubusercontent.com/84855585/132089579-52a96acf-514b-4142-9dab-d56e3854ef5f.png)

![image](https://user-images.githubusercontent.com/84855585/132089613-3ed098f4-8154-4806-8ed0-f50338f39b6c.png)

The malware is now unpacked, and we can use this unpacked exe for analysis.

# Static Analysis of Malware-sample-2

Now that we have the unpacked exe, we put it into TridNet.

![image](https://user-images.githubusercontent.com/84855585/132089685-2b28b387-f518-4a8d-82f2-31ed668d6954.png)

TridNet confirms the file is an .exe file.

Next we take the file into PEStudio

![image](https://user-images.githubusercontent.com/84855585/132089714-26d1f3b2-5a69-4f38-9fef-502517a9e3a3.png)

The first thing we're going to check is that we see there are 7 level 1 indicators.
	1. File is scored by Virustotal
	2. File uses Russian language.
	3. The amount of imports (0) is suspicious.
	4. The first .text section is writable.
	5. The file contains self-modifying executable sections.
	6. The file contains writable and executable sections.
	7. The file references a URL pattern. (69.50.175.181)
	
Using wsock32.dll for websockets/connections.

![image](https://user-images.githubusercontent.com/84855585/132089781-3b3c89b9-ee4b-4afd-8823-602ee7e2d71d.png)

Dialog language in Russian.

![image](https://user-images.githubusercontent.com/84855585/132089787-e2ee9af3-2c25-4074-ac2a-69c538c2cd97.png)






