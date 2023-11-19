---
title: Analyzing DCRat (Dark Crystal RAT)
date: 2023-06-02
subtitle: 
tags: [backdoor,malware,csharp,windows]
comments: true
---

In this post, I will provide an in-depth technical analysis of Dark Crystal RAT, a backdoor written in C#.

## File Metadata
---
`Malware sample`: [here](https://github.com/sk3ptre/AndroidMalware_2020/raw/master/mar_CookieStealer.zip)
<br>
`MD5`: b478d340a787b85e086cc951d0696cb1
<br>
`SHA256`: 8d41d5131fac719cc11823fb57bef9ef1ea063dbb8f52b235a3948bece039d95
<br>
`SHA1`: 563d9f1b35b4898d16aff1dccd8969299f7ab8b7
<br>
`File Size`: 1.2 MB
<br>
`CRC32`: 4a1ebf06

---

## Sandbox Analysis
Running the application in [any.run](https://any.run/) gives us the following process graph.

![](/images/rev/dcr/dcr-01.png')
The original executable drops two executables `mnb.exe` and `dal.exe`. Subsequently, `mnb.exe` drops three executables `fsdffc.exe`,`dfsds.exe` and `daaca.exe`. According to the process graph, `dfsds.exe` seems to do some interesting stuff so let's reverse it first.

## Deobfuscation and Detecting Persistence
```
➜  darkcrystal file dfsds.exe 
dfsds.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```
So, this is a .NET executable. Loading it into DnSpy, a .NET decompiler and decompiling the Main function, we get the following output.

![](/images/rev/dcr/dcr-02.png')

We see that there are multiple calls to the function `ExporterServerManager.InstantiateIndexer` with different arguments which is clearly a sign of obfuscation. Let's try to deobfuscate this executable using [de4dot](https://github.com/de4dot/de4dot).
![](/images/rev/dcr/dcr-03.png')
So, de4dot successfully decompiled it. Let's decompile the deobfuscated binary `dfsds-cleaned.exe`.
![](/images/rev/dcr/dcr-04.png')

As soon as we decompile the `Main()` method, we notice a giant base64 string. Let's decode it and see what's there in it.
```
➜  dcr echo TUhvc3Q6aHR0cDovL2RvbWFsby5vbmxpbmUva3NlemJseGx2b3Uza2NtYnE4bDdoZjNmNGN5NXhnZW80dWRsYTkxZHVldTNxYTU0LzQ2a3FianZ5a2x1bnAxejU2dHh6a2hlbjdnamNpM2N5eDhnZ2twdHgyNWk3NG1vNm15cXB4OWtsdnYzL2FrY2lpMjM5bXl6b24weHdqbHhxbm4zYjM0dyxCSG9zdDpodHRwOi8vZG9tYWxvLm9ubGluZS9rc2V6Ymx4bHZvdTNrY21icThsN2hmM2Y0Y3k1eGdlbzR1ZGxhOTFkdWV1M3FhNTQvNDZrcWJqdnlrbHVucDF6NTZ0eHpraGVuN2dqY2kzY3l4OGdna3B0eDI1aTc0bW82bXlxcHg5a2x2djMvYWtjaWkyMzlteXpvbjB4d2pseHFubjNiMzR3LE1YOkRDUl9NVVRFWC13TGNzOG8xTlZFVXRYeEo5bjl5ZixUQUc6VU5ERUY= | base64 -d
MHost:http://domalo.online/ksezblxlvou3kcmbq8l7hf3f4cy5xgeo4udla91dueu3qa54/46kqbjvyklunp1z56txzkhen7gjci3cyx8ggkptx25i74mo6myqpx9klvv3/akcii239myzon0xwjlxqnn3b34w,BHost:http://domalo.online/ksezblxlvou3kcmbq8l7hf3f4cy5xgeo4udla91dueu3qa54/46kqbjvyklunp1z56txzkhen7gjci3cyx8ggkptx25i74mo6myqpx9klvv3/akcii239myzon0xwjlxqnn3b34w,MX:DCR_MUTEX-wLcs8o1NVEUtXxJ9n9yf,TAG:UNDEF
```
This gives us the configuration that the malware might be using. Reversing it further, we see a function `SchemaServerManager.StopCustomer` that returns a random process name. We can change its name to something meaningful such as `GetRandomProcess`.
```cs
public static string StopCustomer()
{
    Process[] processes = Process.GetProcesses();
    Random random = new Random();
    return processes[random.Next(processes.Length)].ProcessName;
}
```
It copies the executable into the folder containing application data (`%APPDATA%`) and saves it with its name as the random process name generated earlier. After that it checks whether the file `%APPDATA%\dotNET.lnk` exists or not. If it exists, it deletes it otherwise it calls a function `SchemaServerManager.PublishCustomer` with the first argument as `%APPDATA%\dotNET.lnk` and the second argument as `%APPDATA%\randomProcess.exe` where `randomProcess` is the process name generated earlier. This function creates a shortcut `dotNET.lnk` for `%APPDATA%\randomProcess.exe`. After that, it copies the shortcut into the startup folder. Any programs placed inside the startup folder are automatically run when the device starts. It opens the registry key `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` and saves the value `%APPDATA%\dotNET.lnk` into the registry key with the name `scrss`. `Run` is a special registry key that makes the programs listed into it run whenever the user logs in. Once again, it generates a new, random process name and checks whether a file with this name is present in the C drive or not. It also checks for the existence of the existence of the file `Sysdll32.lnk` in the startup folder and the C drive. 

```cs
if (!File.Exists("C:\\" + randomProcess + ".exe") && (!File.Exists(Environment.GetFolderPath(Environment.SpecialFolder.Startup) + "\\Sysdll32.lnk") || !File.Exists("C:\\Sysdll32.lnk")))
...
...
```
If the result of these conditions comes False, it copies the executable into C drive with its name as `<randomProcess>.exe`, creates a shortcut `C:\\Sysdll32.lnk`, copies it to the startup folder, creates a registry value `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Wininit` pointing to `C:\\Sysdll32.lnk`.
All these steps were done to ensure persistence by running the executable at system startup and user-logon. After that, it starts a new process.
```cs
try
{
    Process process = Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\dotNET.lnk");
    if (process.Id >= 2)
    {
        Environment.Exit(0);
        Application.Exit();
    }
    goto IL_7F4;
}
```
If the process successfully starts, the current application is terminated and the new process continues its execution. Further, it creates more files, shortcuts and more registry values. All the shortcuts and registry values created by it are:

### Copies of the executable
```
C:\Users\<username>\AppData\Roaming\<randomProcess>.exe
C:\<randomProcess2>.exe
C:\Users\<username>\Pictures\bkpHst32.exe
```

### Shortcuts
```
C:\Users\<username>\AppData\Roaming\dotNET.lnk
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\dotNET.lnk
C:\Sysdll32.lnk
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Sysdll32.lnk
C:\Users\<username>\Pictures\bkpHst32.lnk
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\bkpHst32.lnk
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Winlog.lnk

```

### Registry Values
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\scrss -> C:\Users\<username>\AppData\Roaming\dotNET.lnk
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Wininit -> C:\\Sysdll32.lnk
HKCU\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\d3dx32 -> <currentFolder>\System.lnk
```

## Detecting multiple instances
After all these steps, the malware sleeps for a random time interval between 5 and 7 seconds, creates and md5 hash of the base64 encoded configuration string we found earlier. 
```cs
private static bool CreateCustomer(string config)
{
	bool result;
	try
	{
		Mutex.OpenExisting(config);
		return false;
	}
	catch
	{
		SchemaServerManager.tokenIdentifier = new Mutex(true, config);
		result = true;
	}
	return result;
}
```
Here, the value of config is `bc2dc004028c4f0303f5e49984983352`. If another instance of the malware is already running, this function returns false and the process exits.

## The Beacon