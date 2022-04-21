# Fun with Mutants, Session Migration, and Self-Deleting Payloads
This repo will cover several different capabilities that may be implemented independently or in conjunction with each other to provide additional functionality in payloads. These capabilties are as follows:

**1. Mutants** - Means by which to prevent several instances of the payload running simultaneously 

**2. Session 1 -> Session 0 Migration** - A technique to obtain a System shell in Session 0 from a user session with Administrator privileges

**3. Self-Deletion** - The ability to delete a file from disk when it is locked by an active process (original credit https://github.com/LloydLabs/delete-self-poc)

The primary focus of this post is to document the development process of each technique and to explain it in some detail, however code samples demonstrating each will also be provided.

This will be an exceptionally long post but I of course encourage you to read it all.  If that needs to be done in chunks, feel free.  I kept this as a single article because in some cases there is cross-over or interaction between the capabilities. 

## Prerequisites

This research was done with two different kinds of payloads in mind:

1. Local injector (LI)
2. Remote Spawn Injector (RSI)

A local injector is the most common and "vanilla" shellcode runner technique.  The ubiquitous VirtualAlloc->memcpy->CreateThread runner is an example of a local injector.  The important takeaway is that the beacon comes from the implant process, which is backed by the payload on disk.

A remote spawn injector differs in that the shellcode runner spawns a new process, injects the shellcode into that process, and then executes the shellcode in that remote process.  As a result the beacon comes from the spawned process, not from the implant process, and the beacon is not backed by the payload on disk.  Note that an RSI is different than a process hollower, as in process hollowing the shellcode is mapped over the original contents of the spawned process, whereas in an RSI new memory is allocated in addition to the already existing memory.

A diagram showing each technique can be seen below:

<img width="1407" alt="image" src="https://user-images.githubusercontent.com/91164728/164479478-063a1706-18d0-46df-b99e-f87cacb0fdf4.png">

There are a few things to address about the RSI graphic.

It is not visually represented, but the call to VirtualAllocEx is listed, as new memory is allocated in the Notepad.exe process.  It should also be noted that Notepad.exe is an example in this case, not a recommended process to spawn for this kind of shellcode runner.

Of note is the Explorer/Winlogon box with the "PPID Spoof" line to Notepad. This implementation of an RSI utilizes Parent Process ID spoofing as an additional evasion technique.  This technique is well documented and as such will not be commented upon except for as how it interacts with and pertains to the capabilities that are the subject of this post.

Explorer and Winlogon are jointly specified because this RSI contains logic to detect the process integrity in which it is running; if it is running in medium integrity, it chooses Explorer.exe as its parent process.  If it is running in high or system integrity it chooses Winlogon.

This design choice has interesting consequences.  

For a LI the beacon will come in at the same integrity level as the process which spawned it.
```
Normal cmd.exe = Medium integrity = Medium integrity beacon

Administrator cmd.exe = High integrity = High integrity beacon
```
Not so with RSI and PPID spoofing…
```
Normal cmd.exe = Medium integrity = Medium integrity beacon

Administrator cmd.exe = High integrity = SYSTEM integrity beacon
```

The RSI shellcode runner returns a system integrity beacon when run as an Administrator because as part of the PPID spoofing process, Winlogon's token is inherited by notepad.exe.  This must be kept in mind, as depending on the kind of access one wants, different shellcode runners may be more appropriate than others (i.e. you have code execution as a domain admin, if you run the LI shellcode runner you will get back a high integrity beacon in a domain context, if you run the RSI you will get back a system integrity beacon on that machine).

This behavior of the RSI adds complications, but also opens the door to new capabilities as will be seen later.

## Mutants

### What is a Mutant?

A mutant is the Microsoft implementation of a mutex. From MSDN (https://docs.microsoft.com/en-us/windows/win32/sync/using-mutex-objects):

``
You can use a mutex object to protect a shared resource from simultaneous access by multiple threads or processes. Each thread must wait for ownership of the mutex before it can execute the code that accesses the shared resource. For example, if several threads share access to a database, the threads can use a mutex object to permit only one thread at a time to write to the database.
``

Mutants can be created in either a session or a global context by means of attaching the prefix "Local\" or "Global\" respectively.

The following code snippet will create a Global mutex which can then be observed using Process Explorer:
```C
void main()
{
	wchar_t mname[255] = L"Global\\MyMutex";
	HANDLE mutanthandle = CreateMutexW(NULL, TRUE, mname);
	Sleep(60000);
}
```

<img width="676" alt="image" src="https://user-images.githubusercontent.com/91164728/164490482-94c89240-02fe-4178-8b60-4d15b9136eeb.png">

That is the legitimate usage of a mutant; but how is that useful in an offensive capacity?

### Mutants in Implants

The usefulness of a mutant in a payload lies not in its ability to control access to a shared resource, but in the fact that it is a system object that can be checked to see whether or not it exists. We choose to use a global mutant, as we want to check for the existence of the mutant accross all sessions as depending on what is happening operationally multiple sessions may be impacted.

There are a myriad of different ways malware can be delivered, executed, and persistence set.  Each time malware runs on a target computer it performs actions that may be detected by AV engines, EDR's, and/or defenders, and as such care should be taken to ensure that 
1. Only necesssary actions are performed
2. Those necessary actions are done in an OPSEC safe manner
3. These actions are not repeated unless necessary.  

Mutants provide a means to address the 3rd line item.  This is a protection against poorly set persistence or unforseen consequences; having several instances of our implant running simultaneously on a single machine increases the IOC's produced and the likelihood of detection.  The base implementation of mutants for this purpose is very simple: On runtime, the implant calls an API to create a named mutex.  Based on the result of that API call, the implant determines whether it successfully created a new mutant, or if a mutant of the same name already exists. A mutant will persist on a machine until the last open handle to it has been closed.  If the mutant already exists, a handle to it must be open, which means the implant must already be running on the machine.

A basic implementation of this can be seen in this code sample:
```C
wchar_t mname[255] = L"Global\\MyMutex";
HANDLE mutanthandle = CreateMutexW(NULL, TRUE, mname);
if(GetLastError() == ERROR_ALREADY_EXISTS)
{
    return 0;
}
else
{
  RunMyPayload();
}
```

The above code calls CreateMutexW to create a global mutex named "MyMutex".  If the mutant already exists, GetLastError() returns ERROR_ALREADY_EXISTS, which means the implant should exit.  Otherwise, execution continues.

That is about as complex as it gets when talking about LI's. With RSI's things get a whole lot more messy, and a whole lot more interesting. 

### This SHOULD be easy...

Recall that a mutant only exists so long as there is an open handle to it; in an RSI runner, payload.exe contains the code to create the mutex.  It also spawns a new process and injects the shellcode into it, resulting in a beacon not from the payload.exe process but from the spawned process. After the beacon has been started, the payload.exe process exits, and with it, the handle to the mutex is closed; however there is still an active beacon on the system, and a subsequent attempt to run payload.exe will succeed because the mutant no longer exists. In order for this capabilitiy to work as intended the spawned process must have a handle to the mutant, as it is the spawned process that contains the beacon and thus is the one that matters. 

The prototype for the CreateMutexW function is as follows(https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw):

```C
HANDLE CreateMutexW(
  [in, optional] LPSECURITY_ATTRIBUTES lpMutexAttributes,
  [in]           BOOL                  bInitialOwner,
  [in, optional] LPCWSTR               lpName
);
```
On the same page in the remarks section it is noted that:

``A child process created by the CreateProcess function can inherit a handle to a mutex object if the lpMutexAttributes parameter of CreateMutex enabled inheritance. This mechanism works for both named and unnamed mutexes.``

Armed with this knowledge, the path forward is fairly obvious; create the security structure, populate it appropriately, and pass the handle to the mutant to the spawned process via the CreateProcess call.  Of course it can't be that easy.

The most common technique by which PPID Spoofing is implemented involves using UpdateProcThreadAttribute and the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute, specifying a handle to the intended parent process.  Per MSDN(https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute):

```
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

...

Attributes inherited from the specified process include handles, the device map, processor affinity,
priority, quotas, the process token, and job object.

...
```
So what happens when we try to pass the handle to the spawned process via CreateProcess AND implement PPID spoofing? Truth be told, I am writing this article a week after developing all this and don't remember which way it cut; either the spawned process successfully received the mutant handle but PPID spoofing failed, or PPID spoofing succeeded but the spawned process did not receive a handle to the mutant.  Regardless, if we want the spawned process to have a handle to the mutant AND have PPID spoofing, a change in tactics is needed.

### Juggling Handles

The stub for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS notes that handles from the parent process are inherited by the child process.  If we can give the parent process we wish to spoof a handle to the mutant, it should be inherited by the spawned process. Enter DuplicateHandle(https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle):

```C
BOOL DuplicateHandle(
  [in]  HANDLE   hSourceProcessHandle,
  [in]  HANDLE   hSourceHandle,
  [in]  HANDLE   hTargetProcessHandle,
  [out] LPHANDLE lpTargetHandle,
  [in]  DWORD    dwDesiredAccess,
  [in]  BOOL     bInheritHandle,
  [in]  DWORD    dwOptions
);
```

Most typical examples of this API that you will find use it in order to "get" a handle from another process or to duplicate a handle within the local process. In our case we will use it to "give" the payload processes mutant handle to the parent process as shown below

<img width="677" alt="image" src="https://user-images.githubusercontent.com/91164728/164518223-01cb26d8-6bfb-4a06-a701-4284ff58b64e.png">

After calling DuplicateHandle() the parent process also has a handle to the mutex, and when CreateProcess is called utilizing PPID spoofing the spawned process inherits the handle to the mutex as desired.

<img width="842" alt="image" src="https://user-images.githubusercontent.com/91164728/164520239-a18eae5c-e97a-46a7-a873-88f5cc8e3b5f.png">

There is however yet another problem. After payload.exe finishes spawning and injecting Notepad.exe, it exits, closing its handle to the mutant.  When the beacon is eventually exited, its handle to the mutant is closed. Upon trying to run the payload again, it will not create a new beacon because the parent process still has its handle to the mutant.  In order to remove the handle DuplicateHandle() must be called again, this time in reverse, and with the DUPLICATE_CLOSE_SOURCE flag specified.  This will duplicate the handle that the parent process holds to the mutant back to payload.exe and in doing so close the handle that the parent holds.  Payload.exe will now have two handles to the mutex, both of which will exit when it does.  The final sequence of events regarding the handles is as follows:

<img width="864" alt="image" src="https://user-images.githubusercontent.com/91164728/164522155-c04d157c-6c25-4ab5-b1bf-0e23003a8c77.png">

1. CreateMutex() is called to create the mutant
2. DuplicateHandle() is called to pass the mutant handle to the parent process
3. CreateProcess is called with PPID Spoofing, passing the mutant handle to Notepad.exe
4. DuplicateHandle() is called a second time with the DUPLICATE_CLOSE_SOURCE flag to remove the handle from the parent process
5. Payload.exe exits, closing its handles to the mutant
6. Notepad.exe holds the only remaining open handle to the mutant.  When the beacon exits, the mutant will be removed, and the payload may successfully run again.

Success!

### Making it smarter

We have successfully implemented mutants into the RSI model shellcode runner, preventing multiple instances of payload.exe from running.  Note that it does NOT prevent additional beacons on the machine created via different methods, like through Cobalt Strikes Shinject command.  What are the limitations of this capability as it has been implemented?

The shellcode runner logic checks for the existence of a specific named mutant; if the mutant name is static and hardcoded into the runner, it would prevent, for example, the payload being able to be ran by different users on the same machine.  This is undesirable as one might obtain code execution in a privileged context and wish to use it to kick another beacon.  Another possible limitation exists when talking about alternate communication channels; suppose there is a long standing, infrequently calling back DNS beacon that has been maintained until the time comes for active effects against the machine, at which point an HTTPS beacon is desired due to their vastly superior data transfering abilities. If the mutant name is hardcoded into each generated payload, this alternate channel beacon would be prevented from running by the presence of the mutant from the DNS beacon.

To address these issues name generation for the mutant has been made dynamic. The mutant name will now comprise of two parts:

1. The data channel (HTTPS, DNS, etc)
2. The username of the context running it (Tim, Administrator, System, etc.)

By combining these two variables a more unique mutant name can be created which will allow the following:

1. The same user may run payloads of different communication channel types
2. Different users may run the same payload
3. The same user may run the same payload in different integrities (normal cmd.exe vs Administrator cmd.exe.  Requires some more work but possible)

and prevent:

1. The same payload being ran by the same user in the same integrity.  

The case that is prevented is the one which would result from a persistence method ran awry.

In order to add some measure of tradecraft and prevent the existence of a named mutex called "HTTPSAdministrator", the combined name is ran through a hashing function to produce a unique number which will serve as the name:

<img width="201" alt="image" src="https://user-images.githubusercontent.com/91164728/164530926-2a9ebf99-2c60-41e7-9051-fa8c17a7c9ca.png">

The POC that is provided demonstrates this fully fleshed out mutant capability in the PPID Spoofing RSI implementation; implementing the working mutant name dynamic generation allowing the same user to run the same payload in different integrities in a LI shellcode runner will be left as an exercise to the reader. 

## Session 1 -> Session 0 Migration

When the RSI shellcode runner was developed and the ability to receive a beacon as system from a high integrity prompt observed, a false sense of security set in due to a failure to differentiate system integrity and the system session.  A (wrong) assumption was made that because the beacon was running as system it would persist even after the user who we executed the payload as logged out;  it was during all of the testing involving mutants that this error was finally realized which posed the question: is it possible to spawn a session 0 process from session X (a user session)?

Typically to run a beacon in session 0 a service is created to run as system, however I was curious to find out if there was a way to do so without creating hard persistence on the machine.  What followed was a long and painful journey into process tokens. 
