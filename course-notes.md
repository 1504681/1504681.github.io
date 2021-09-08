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

## Bintext Analysis

![image](https://user-images.githubusercontent.com/84855585/132315368-76311650-b7a7-4c35-bb98-3a31d8de9f71.png)

Here we can see the following strings:
	GetStartupInfoA
	RegDeleteKeyA
	RegSetValueExA
	RegDeleteValueA
	RegCreateKeyExA
	RegQueryValueExA
	RegCloseKey
	
![image](https://user-images.githubusercontent.com/84855585/132315634-e3e232fb-2c70-4c31-93e6-4f4f7a04b825.png)

We also see some HTML of a fake error message:

![image](https://user-images.githubusercontent.com/84855585/132315876-e1b51e5e-b2ae-408a-815c-6b9e3ef356ad.png)

We also see a HTTP download request:

![image](https://user-images.githubusercontent.com/84855585/132315986-a948c586-9dca-4497-8e89-63127f784fbf.png)

So we can assume this software will use scare tactics (with the fake error message) to promt the user to download a fake antivirus software (BraveSentry)

Evidenced here: 

![image](https://user-images.githubusercontent.com/84855585/132316227-9248d7ea-b083-4e18-9048-7a62e7ff2cc2.png)

We see a Registry key string "SOFTWARE\Microsoft\Windows\CurrentVersion\Run", followed by "C:\\Windows\xpupdate.exe". This is likely a persistence executable to be run at startup.

![image](https://user-images.githubusercontent.com/84855585/132316649-52a0038b-3ec9-4924-814a-04590a570ebe.png)

## Searching for encrpted string with xorsearch

In CMD, we're going to run the xorsearch command followed by the unpacked malware file as the first parameter, the second parameter will be the string we're going to be searching for, "http".

![image](https://user-images.githubusercontent.com/84855585/132317170-2f35aa31-838d-4448-a11d-d8e59694b254.png)

Now after this, we get 5 results.

![image](https://user-images.githubusercontent.com/84855585/132317296-8bab029b-4b6a-4905-ac43-91730d3caf88.png)

With XOR 00, this means there was NO encryption, so we can ignore this result.
With XOR 20, these conversions were lowercase/uppercase conversions.

Therefor, we did not get any encrypted results through this search, so we can try with a different string, "This".

We search for "This" because we know that at the start of PE files, there is always the string "This program cannot be run in DOS mode", therefor if we find this string with or without encryption, we can make assumptions about the encrpytion of the rest of the file.

Now for the results:

![image](https://user-images.githubusercontent.com/84855585/132317729-624abd4a-0262-4842-9b58-ac22ec7029f4.png)

With another XOR 00 result, we can assume that the file is NOT encrypted.

## HashAnalysis

In PEStudio, we can take the programs MD5 hash, copy it and take it into VirusTotal for the results.

![image](https://user-images.githubusercontent.com/84855585/132318595-5416d510-a53b-4434-8c4e-c7b859f880a1.png)


![image](https://user-images.githubusercontent.com/84855585/132318558-5a39248f-e8fe-41ee-920a-4534fc198f87.png)

And VirusTotal already has 40 flags for this unpacked exe file.

![image](https://user-images.githubusercontent.com/84855585/132318685-dafd4161-7dc0-4e77-8bc5-ca00534b32fc.png)

We can conclude from all of these results that this is a malicious executable.

Next, we can process with the Dynamic analysis.

# Dynamic Analysis of Malware-Sample-2

1) Open procmon, stop capturing & clear the results.

![image](https://user-images.githubusercontent.com/84855585/132319046-9e5be957-7a11-4b15-9646-a1331d0402cc.png)

2) Open Fakenet to intercept network traffic

![image](https://user-images.githubusercontent.com/84855585/132319280-54e96e5e-2342-4dac-b945-b49a8e8794c3.png)


3) Open Regshot, and make sure we are scanning the entire C:\ Drive, take 1st shot.

![image](https://user-images.githubusercontent.com/84855585/132319690-fb96ec8c-c1d1-4b51-b807-fe66968bfd13.png)

4) In procmon, turn "Capture" back on, and run the malware with elevated privledges. We saw earlier that the malware is writing to the protected "C:\Windows\" folder, so we are sure that it needs administrative privledges to work.

![image](https://user-images.githubusercontent.com/84855585/132326782-a53f52a0-4aa5-4606-be5e-b23cf475a01f.png)


We can see through Fakenet that the malware requested a TCP download, likely to download more malware packages:

![image](2021-09-08-10-06-35.png)

Now we'll take our 2nd shot and compare the two Regshots

Here we see 9 new registry values added:

![image](2021-09-08-10-11-36.png)

We can see the malware has installed persistence in the \SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ folder, with "Windows update loader: "C:\Windows\xpupdate.exe"


![image](2021-09-08-10-13-25.png)

We will add this file to our notes to check again later

![image](2021-09-08-10-18-06.png)

another persistence key would be the following key: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run\con: "C:\Users\ThomasK\Desktop\malware-sample\financials-xls-unpacked.exe" which will execute this malware program again on startup.

Under files added, we see 5 files have been created:

![image](2021-09-08-10-16-27.png)

We take note of "C:\Users\ThomasK\AppData\Roaming\Install.dat"
as well.


## Procmon Filters & Export

As explained before, we're going to filter for results pertaining to this malware executable.

![image](2021-09-08-10-21-06.png)

Add the rest of our filters:

![image](2021-09-08-10-22-41.png)

Results:

![image](2021-09-08-10-23-18.png)

We can see the two new files, xpupdate.exe and Install.dat, and we see the 3 new RegSetValue's.

Again we will export as PML & CSV formats.

We'll save both of these files to the malware the folder is in.

![image](2021-09-08-10-25-40.png)

### Procdot Analysis

After adding the CSV file from Procmon into ProcDOT, we get this graph:

![image](2021-09-08-10-36-14.png)

We can see:
	The TCP connection with the webserver 69.50.175.181

	Thread 8180 created file C:\Windows\xpupdate.xe
	Thread 8180 created registry key "Windows update loader" which is an Autostart Registry key

	Thread 8180 created thread 4260
		Thread 4260 created the Install.dat file.
		Thread 4260 created 2 more registry keys, one of them being the \Run\con autostart key.
		Thread 4260 also killed the original malware process

### Compare Hashes with PEStudio

If we compare the hashes of the file this malware created, with the original malware itself, we actually can see that they are the exact same file.

![image](2021-09-08-10-44-00.png)


# Network Analysis of Malware-sample-2



