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

We use Wireshark to open the .pcap file generated by Fakenet, and filter for HTTP, because we saw that the malware attempted to connect to a webserver to download a file.

![image](2021-09-08-10-48-52.png)

Now we can find the request, and Right Click -> Follow TCP Stream

![image](2021-09-08-10-50-32.png)

It made the request to download a file at download.bravesentry.com

# Indicators of Compromise Report

In the file system we had the files:
	C:\Windows\xpupdate.exe
	Install.dat

In the registry we found evidence of:
	Two persistence keys

In the network analysis we found evidence of:
	TCP download request to download.bravesentry.com'


