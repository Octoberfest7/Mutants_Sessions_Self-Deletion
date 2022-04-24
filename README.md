# Fun with Mutants, Session Migration, and Self-Deleting Payloads
This repo will cover several different capabilities that may be implemented independently or in conjunction with each other to provide additional functionality in payloads. These capabilties are as follows:

**1. [Mutants](#mutants)** - Means by which to prevent several instances of the payload running simultaneously 

**2. [Session 1 -> Session 0 Migration](#session-1---session-0-migration)** - A technique to obtain a System shell in Session 0 from a user session with Administrator privileges

**3. [Self-Deletion](#self-deletion)** - The ability to delete a file from disk when it is locked by an active process (original credit belongs to [LloydLabs](https://github.com/LloydLabs/delete-self-poc))

The primary focus of this post is to document the development and/or implementation process of each technique and to explain it in some detail, however code samples demonstrating each will also be provided.

This will be an exceptionally long post but I of course encourage you to read it all.  If that needs to be done in chunks, feel free.  I am publishing this as a single article because the development process of these capabilities occurred in tandem around a common shellcode runner.

## Prerequisites

This research was done with two different kinds ofshellcode runners in mind:

1. Local injector (LI)
2. Remote Spawn Injector (RSI)

A local injector is the most common and "vanilla" shellcode runner technique.  The ubiquitous VirtualAlloc->memcpy->CreateThread runner is an example of a local injector.  The important takeaway is that the beacon comes from the implant process, which is backed by the payload on disk.

A remote spawn injector differs in that the shellcode runner spawns a new process, injects the shellcode into that process, and then executes the shellcode in that remote process.  As a result the beacon comes from the spawned process, not from the implant process, and the beacon is not backed by the payload on disk.  Note that an RSI is different than a process hollower, as in process hollowing the shellcode is mapped over the original contents of the spawned process, whereas in an RSI new memory is allocated in addition to the already existing memory.

A diagram showing each technique can be seen below:

![image](https://user-images.githubusercontent.com/91164728/164955994-7bfcfa57-8959-4609-a314-4526fcbf11ab.png)


There are a few things to address about the RSI graphic.

It is not visually represented, but the call to VirtualAllocEx is listed, as new memory is allocated in the Calc.exe process.  It should also be noted that Calc.exe is an example in this case, not a recommended process to spawn for this kind of shellcode runner.

Of note is the Explorer/Winlogon box with the "PPID Spoof" line to Calc. This implementation of an RSI utilizes Parent Process ID spoofing as an additional evasion technique.  This technique is well documented and as such will not be commented upon except for as how it interacts with and pertains to the capabilities that are the subject of this post.

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

The RSI shellcode runner returns a system integrity beacon when run as an Administrator because as part of the PPID spoofing process, Winlogon's token is inherited by Calc.exe.  This must be kept in mind, as depending on the kind of access one wants, different shellcode runners may be more appropriate than others (i.e. you have code execution as a domain admin, if you run the LI shellcode runner you will get back a high integrity beacon in a domain context, if you run the RSI you will get back a system integrity beacon on that machine).

This behavior of the RSI adds complications, but also opens the door to new capabilities as will be seen later.

## Mutants

### What is a Mutant?

A mutant is the Microsoft implementation of a mutex. From [MSDN](https://docs.microsoft.com/en-us/windows/win32/sync/using-mutex-objects):

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

The prototype for the [CreateMutexW](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw) function is as follows:

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

The most common technique by which PPID Spoofing is implemented involves using UpdateProcThreadAttribute and the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute, specifying a handle to the intended parent process.  Per [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute):

```
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

...

Attributes inherited from the specified process include handles, the device map, processor affinity,
priority, quotas, the process token, and job object.

...
```
So what happens when we try to pass the handle to the spawned process via CreateProcess AND implement PPID spoofing? Truth be told, I am writing this article a week after developing all this and don't remember which way it cut; either the spawned process successfully received the mutant handle but PPID spoofing failed, or PPID spoofing succeeded but the spawned process did not receive a handle to the mutant.  Regardless, if we want the spawned process to have a handle to the mutant AND have PPID spoofing, a change in tactics is needed.

### Juggling Handles

The stub for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS notes that handles from the parent process are inherited by the child process.  If we can give the parent process we wish to spoof a handle to the mutant, it should be inherited by the spawned process. Enter [DuplicateHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle):

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

Most typical examples of this API that you will find use it in order to "get" a handle from another process or to duplicate a handle within the local process. In our case we will use it to "give" the payload process's mutant handle to the parent process as shown below

<img width="677" alt="image" src="https://user-images.githubusercontent.com/91164728/164518223-01cb26d8-6bfb-4a06-a701-4284ff58b64e.png">

After calling DuplicateHandle() the parent process also has a handle to the mutex, and when CreateProcess is called utilizing PPID spoofing the spawned process inherits the handle to the mutex as desired.

![image](https://user-images.githubusercontent.com/91164728/164956127-c0c9e4e7-dcb5-49b3-a296-7ed91b51e196.png)

There is however yet another problem. After payload.exe finishes spawning and injecting Calc.exe, it exits, closing its handle to the mutant.  When the beacon is eventually exited, its handle to the mutant is closed. Upon trying to run the payload again, it will not create a new beacon because the parent process still has its handle to the mutant.  In order to remove the handle DuplicateHandle() must be called again, this time in reverse, and with the DUPLICATE_CLOSE_SOURCE flag specified.  This will duplicate the handle that the parent process holds to the mutant back to payload.exe and in doing so close the handle that the parent holds.  Payload.exe will now have two handles to the mutex, both of which will exit when it does.  The final sequence of events regarding the handles is as follows:

![image](https://user-images.githubusercontent.com/91164728/164956056-c3f2451f-6d62-4048-a1d5-41e90c913fc9.png)

1. CreateMutex() is called to create the mutant
2. DuplicateHandle() is called to pass the mutant handle to the parent process
3. CreateProcess is called with PPID Spoofing, passing the mutant handle to Calc.exe
4. DuplicateHandle() is called a second time with the DUPLICATE_CLOSE_SOURCE flag to remove the handle from the parent process
5. Payload.exe exits, closing its handles to the mutant
6. Calc.exe holds the only remaining open handle to the mutant.  When the beacon exits, the mutant will be removed, and the payload may successfully run again.

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

The POC that is provided demonstrates a partial implementation of the mutant capability as described here; it does not account for a user running the same payload in a normal vs an elevated context, nor the special cirumstance encountered in the RSI runner where the payload is ran by a user, but the beacon comes back as system.  These issues have been addressed in the operational implementation of this capability. 

## Session 1 -> Session 0 Migration
### Background

When the RSI shellcode runner was developed and the ability to receive a system integrity beacon from a high integrity prompt observed, a false sense of security set in due to a failure to differentiate system ***integrity*** and the system ***session***.  An assumption was made that because the beacon was running as system it would persist even after the user who executed the payload logged out; the flaw in this logic being that the system integrity Calc.exe spawned by the RSI runner still exists in session 1, or a user's session.  When a user logs out, all of the processes belonging to their user session exit (as a side note, locking the user session or switching users does not exit the user session and all of the user's processes continue to run), and as such Calc.exe exits taking the beacon with it. Now aware of this problem, the question can be asked: is it possible to spawn a session 0 process from a user session?

Typically to run a process in session 0 a service is created to run as system, however I was curious to find out if there was a way to do so without creating hard persistence on the machine.  What followed was a long and painful journey into process tokens, integrity levels, and Win32API's involved in token manipulation. 

### A quick primer on system processes

We are going to be talking about impersonating, duplicating, and modifying the token of system integrity processes.  Because nothing can ever be easy, there are some complications and idiosyncrasies that need to be addressed.  This article by [SpecterOps](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b) is a great exploration of this topic and was referenced during this work.  

When running cmd.exe as an Administrator there are a laundry list of privileges available for use: 

![image](https://user-images.githubusercontent.com/91164728/164984164-9b115d46-0754-4b18-90db-abb4d7285302.png)

It should be noted that as long as a privilege is listed, it may be used; it may be listed as disabled currently, but enabling it is a trivial task. 

Of particular use are the SeDebugPrivilege and the SeImpersonatePrivilege.  With these (after they are both enabled), an individual can successfully open a handle to a system integrity process (and token) and impersonate it's token, gaining system level integrity.  After playing with this ability a bit, one will notice that some system integrity processes seem to be more accessible than others; this quirk was dialed in on by the author of the SpecterOps article, who found that the critical difference lies in the TokenOwner property of a process.  This can be observed in the following image comparing winlogon.exe with spoolsv.exe:

![image](https://user-images.githubusercontent.com/91164728/164984441-7b67ce40-4f79-45d6-9246-4364aa26ff16.png)

Note that the owner of winlogon is "Administrators", while the owner of spoolsv is "LogonSessionId_0...". The impact on our work here is that from an Administrator prompt a handle can be opened to winlogon and it's token impersonated, and while a handle can be opened to spoolsv, it's token may not be opened in order to impersonate it.  If one were to want to access the token of spoolsv, or another system integrity process's that is not owned by Administrators, they will first need to impersonate system (most easily done by opening winlogons process/token and calling ImpersonateLoggedOnUser()) before they will be able to do so.  

Another wrinkle comes in when PPL protected processes are encountered.  The specifics of PPL protection will not be covered here, but for our purposes PPL protection can be summarized as an additional layer of security/protection on a process that greatly inhibits userland interaction with it.  PPL protection can be observed on several system processes, to include wininit.exe, smss.exe, MsMpEng.exe, and services.exe.  Smss.exe is viewed in ProcessExplorer where its PPL status can be observed as "PsProtectedSignerWinTcb-Light":

![image](https://user-images.githubusercontent.com/91164728/164984761-90833417-1096-4274-b7cf-e07b03672756.png)

There are a few things to note about PPL protection and it's impact on our work:

1. PPL protection limits the permissions with which a handle to a process may be opened to PROCESS_QUERY_LIMITED_INFORMATION.

	A. PPID spoofing requires PROCESS_CREATE_PROCESS access; as a result, PPID spoofing may not be done using a PPL protected process.
	
	B. PROCESS_QUERY_LIMITED_INFORMATION DOES allow for token duplication and impersonation.
	
2. Strangely, many of the PPL protected processes belong to Administrators and reside in session 0, which means handles CAN be opened to them without needing to first impersonate system.
3. PPL protection extends to memory as well; one cannot inject into a PPL protected process or end a PPL protected process from userland.  

### Where to start?

The first question to answer is, "What dictates what session a process belongs to?".  In our situation the most obvious options are either:

1. It is the user who calls CreateProcess() 
2. It is the parent process when PPID Spoofing is done

Given that winlogon lives in session 1 and that it is the target of our PPID spoofing, an assumption might be made that calc.exe will also spawn in session 1 as a result.  A simple test of this may be conducted by using a session 0 system integrity process like spoolsv.exe for PPID spoofing instead; in doing so we find that Calc.exe still resides in session 1:

![image](https://user-images.githubusercontent.com/91164728/164956285-32cc8013-6389-4b6f-ad95-ad72e99c9237.png)

So it doesn't seem to be the assigned parent process that impacts the child process's session.  Time to look at our other possibility.  The seemingly simplest solution is to gain system integrity via a call to ImpersonateLoggedOnUser() using a handle to a session 0 process, and then call CreateProcess() to spawn Calc.exe which will hopefully reside in session 0.  A small POC was put together to test this in which:

1. A handle to smss.exe is opened (system integrity process in session 0)
2. ImpersonateLoggedOnUser() is called referencing that handle
3. GetUserName() is called which returns that our process is now SYSTEM
4. GetTokenInformation() is called to retrieve the session ID of our process's token
5. CreateProcess() is called to spawn Calc.exe

The result of which is:

![image](https://user-images.githubusercontent.com/91164728/164982050-caf90459-1a69-4cb5-9131-0a7b17bf41ac.png)

As can be seen in this screenshot of the console output of this code, system is successfully impersonated; however GetTokenInformation reveals that the SessionId of our process's token is still 1, and as a result the call to CreateProcess() still yields a Calc.exe in session 1.  We will need to go deeper.

### More research needed

A google search turned up some relevant StackOverflow posts about this topic ([Here](https://stackoverflow.com/questions/66226029/windows-create-a-process-in-session-0-using-createprocesswithtokenw) and [Here](https://stackoverflow.com/questions/38427094/createprocessasuser-works-createprocesswithtokenw-does-not/38442543#38442543)) where an exceptionally knowledgable user named RbMm provided some much needed and seemingly otherwise hard to come by information.  

Two additional API's exist when it comes to creating a process as a different user; CreateProcessWithToken() and CreateProcessAsUser(). The above StackOverflow links delve heavily into this and ultimately reveal that CreateProcessWithToken() is in fact a wrapper for CreateProcessAsUser(), and as part of the function call it sets the SessionId back to the original session of the calling process; all this means that for our purposes, if we want to create a process with a session id different than that of our calling process, we need to use CreateProcessAsUser() and do a little more work manually.  [This](https://stackoverflow.com/questions/39238086/running-process-in-system-context) StackOverflow post, again from RbMm, provides more critical information:

```
To "launch a process in the system context", if you want to run the process:

-with the LocalSystem token.

-in the System terminal session (0)

Both, as I say, are possible. And all you need is SE_DEBUG_PRIVILEGE.

1. more simply - open some system process with PROCESS_CREATE_PROCESS access right. Use this handle with UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). As a result, your started process inherits a token from the system process. This will be not work on XP, but there it is possible to hook NtCreateProcess/Ex() to replace HANDLE ParentProcess with your opened handle.

2. Another way is to use CreateProcessAsUser(). Before creating the process, you will be need SE_ASSIGNPRIMARYTOKEN_PRIVILEGE and SE_TCB_PRIVILEGE privileges to set the token's TokenSessionId (if you want to run in session 0).
```

Method 1 in the above quote is largely what was already tried; I went back and ensured that PROCESS_CREATE_PROCESS was specified with spoolsv.exe, and while the resultant calc.exe DID have system integrity, it still resided in session 1.  On to method 2. 

### Finally some code

As mentioned in method 2, SE_ASSIGNPRIMARYTOKEN_PRIVILEGE and SE_TCP_PRIVILEGE are required to successfully use CreateProcessAsUser(); unfortunately Administrators do not possess either.  The first step will be to impersonate a system token that does possess these privileges; in order to do so the SeDebugPrivilege must first be enabled in our shellcode runner's token:

![image](https://user-images.githubusercontent.com/91164728/164985876-834e580f-fe1e-437d-851f-7ab3e652f052.png)

There are many choices; spoolsv, winlogon, and smss all have the desired privileges, but there are a few things to be considered. Spoolsv cannot be immediately impersonated since it does not belong to Administrators, so an initial impersonation would need to be done of another system integrity process.  Winlogon could be used to gain these privileges but it resides in session 1.  Smss could be impersonated, it does reside in session 0, however it is PPL protected.

For this initial step, winlogon is the most obvious choice as the session is not important yet; our process simply needs the privileges in question.  Winlogon will be used for now, but this will be revisited later.

![image](https://user-images.githubusercontent.com/91164728/164986090-fe0a1e57-8ae5-495e-83af-443dbab9c6c8.png)

After impersonating winlogon's token, the SE_ASSIGNPRIMARYTOKEN_NAME privilege must be enabled in our token.  Note that OpenThreadToken() and GetCurrentThread() are used as opposed to OpenProcessToken() and GetCurrentProcess(), as the impersonated token resides in the current thread:

![image](https://user-images.githubusercontent.com/91164728/164990815-71a3005a-f869-436c-8ba5-0bf27c4631e6.png)

At this point a handle to a session 0 process needs to be opened and DuplicateToken() called to create a copy of it's token for use with CreateProcessAsUser().  Given that our shellcode runner is now running with system integrity, spoolsv could be utilized as it meets this criteria; there is an additional consideration however.  The spawned calc.exe will inherit the permissions of the token used in CreateProcessAsUser().  Looking at spoolsv's permissions shows some important ones, however it is a far shorter list than a lot of other system integrity process's permissions:

![image](https://user-images.githubusercontent.com/91164728/164986384-f14150de-83e3-40e1-8e64-3e7b913f983d.png)

It seems desirable to duplicate a different session 0 process's token that has more privileges if possible, as one never knows when they might come in handy.  To do so we will shift our focus to smss.exe.

As mentioned this is a PPL protected process, however even with that being the case, its token can be duplicated for use with CreateProcessAsUser().  What's more, it has the requisite permissions to call CreateProcessAsUser(), so we can consolidate steps by impersonating smss.exe and enabling privileges within that impersonated token instead of doing so with winlogon; this will allow us to call DuplicateToken() using the same open handle used for ImpersonateLoggedOnUser().  Combining these steps yields the following code:

![image](https://user-images.githubusercontent.com/91164728/164990798-fb8f687c-e384-4e6e-a406-e86149361eb1.png)

Finally, CreateProcessAsUser() may be called to create notepad.exe in session 0 (Note that notepad.exe was used in this example as calc.exe was exiting instantly without shellcode injected into it):

![image](https://user-images.githubusercontent.com/91164728/164986766-92f2a728-86ba-45d7-ae93-8562fcf5ca95.png)

And the resultant notepad.exe:

![image](https://user-images.githubusercontent.com/91164728/164986816-314aa51f-3e4f-4705-a2ff-034f5f87bc7d.png)

Success! 

Unfortunately, as previously mentioned, it is not possible to use a PPL protected process (which most of the always-present, default session 0 processes are) for PPID spoofing; ideally we want a process in session 0 as the parent for the session 0 spawned process. While spoolsv wasn't an ideal candidate for token duplication due to its limited privileges, it is a fine candidate for PPID spoofing (to reiterate, in the operational deployment of these techniques a different process than calc.exe or notepad.exe is spawned which makes a lot more sense than either of those to exist as a child process of spoolsv). When the session migration code is combined with the normal PPID spoofing code and injection with shellcode, the result is a calc.exe running in session 0, with all of the privileges of smss.exe, with spoolsv.exe as its parent PID:

![image](https://user-images.githubusercontent.com/91164728/164990184-be7a4073-4669-4cb8-b21f-56c8bc30dff4.png)

A large IOC of this technique is that it is abnormal for a child process to have greater privileges than its parent; however in testing this has not proven to be an issue against a major vendor's EDR. 

The POC provided for this capability demonstrates everything walked through above with the exception of PPID spoofing.  Implementing PPID spoofing in conjunction with this capability is trivial and left to the reader to accomplish.

## Self-Deletion
### Background

This is a capability that [LloydLabs](https://github.com/LloydLabs/delete-self-poc) created a POC for.  The idea is to delete a file that is locked on disk by a running process; this has interesting implications whether talking about a LI or an RSI shellcode runner.  With an RSI runner, Payload.exe will exit and thus be deletable after the beacon process has spawned, so there is not necessarily anything ground breaking here besides the fact that we can automate cleanup; however in a LI runner, Payload.exe is locked for as long as our beacon process exists, and in this case being able to delete Payload.exe from disk while maintaining our beacon in memory is an interesting option.  In situations where reflective loading and other means to start beacons entirely in memory are not possible and dropping a file to disk is unavoidable, being able to delete the initial payload and then place persistence elsewhere via the now-running beacon may assist in breaking up patterns and telemetry that would be better not handed so obviously to defenders. 

The following is copied and pasted from the LloydLabs ReadMe describing how the POC works:

```
1. Open a HANDLE to the current running process, with DELETE access. Note, DELETE is only needed.
2. Rename the primary file stream, :$DATA, using SetFileInformationByHandle to :wtfbbq.
3. Close the HANDLE
4. Open a HANDLE to the current process, set DeleteFile for the FileDispositionInfo class to TRUE.
5. Close the HANDLE to trigger the file disposition
6. Viola - the file is gone.
```

Seeing as the POC already exists, the code will not be covered in near as much detail here; only a specific few sections will be highlighted to address issues and demonstrate novel implementations.

### Fixing a memory issue

The ds_rename_handle function at line 14 of [main.c](https://github.com/LloydLabs/delete-self-poc/blob/main/main.c) contains an error, specifically on line 24 (RtlCopyMemory call).  The entire function is shown here (slightly modified to remove a definition stored in main.h):

```C
static
BOOL
ds_rename_handle(
	HANDLE hHandle
)
{
	FILE_RENAME_INFO fRename;
	RtlSecureZeroMemory(&fRename, sizeof(fRename));

	// set our FileNameLength and FileName to DS_STREAM_RENAME
	LPWSTR lpwStream = L":wtfbbq";
	fRename.FileNameLength = sizeof(lpwStream);
	RtlCopyMemory(fRename.FileName, lpwStream, sizeof(lpwStream));

	return SetFileInformationByHandle(hHandle, FileRenameInfo, &fRename, sizeof(fRename) + sizeof(lpwStream));
}
```

The issue lies in that RtlCopyMemory attempts to move L":wtfbbq" into fRename.FileName.  [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info) has the definition for FILE_RENAME_INFO which reveals the problem:

```C
typedef struct _FILE_RENAME_INFO {
  union {
    BOOLEAN ReplaceIfExists;
    DWORD   Flags;
  } DUMMYUNIONNAME;
  BOOLEAN ReplaceIfExists;
  HANDLE  RootDirectory;
  DWORD   FileNameLength;
  WCHAR   FileName[1];
} FILE_RENAME_INFO, *PFILE_RENAME_INFO;
```
There are only two bytes allocated for the FileName property of the structure (1 wchar @ 2 bytes ea), yet the program is stuffing 14 bytes (7 wchars @ 2 bytes each) into this space. This is a confusing structure that StackOverflow reveals has tripped up quite a few people and while the POC does function, it is better to fix this before using it in production.

The length of lpwStream must be calculated and added to the length of the base FILE_RENAME_INFO structure, before calling malloc in order to allocate enough memory to hold the entire structure.  After that has been done the structure can be populated as before with the renamed stream before SetFileInformationByHandle() is called:

![image](https://user-images.githubusercontent.com/91164728/164995364-2fe55527-517b-459a-819f-53da1b832595.png)

With the memory issue fixed, discussion can proceed to the actual implementation of this code in a shellcode runner.

### Weaponization

Having Payload.exe delete itself may not always be the desired behaviour; to address this a few simple lines of code will look for any arguments to payload.exe and, should there be any (regardless of what they are), Payload.exe will not delete itself:

```C
    if (argc > 1)
    {
        ;
    }
    else
    {
        deleteme();
    }
```

This opens the door to Payload.exe being reused in persistence scenarios, with the added benefit of being able to do some base-level obfuscation by specifying command line args to pass to it in the case of a scheduled task or service without any impact to the actual function of the shellcode runner (e.g. MSUpdater.exe /Check-all /Force-Update).

In the case of a DLL, a few things have to be tweaked for the self-deletion tactic to succeed.  For the purposes of demonstration rundll32.exe will be used to run the DLL format shellcode runner.

The original POC calls GetModuleFileNameW() in order to get the full path of the currently running process. This works just fine in a .exe implementation, but in a DLL where another process is loading and running the DLL (rundll32.exe in this instance), the original code returns the path to rundll32.exe (or whatever application was used to sideload our malicious DLL) whch we certainly do not want to delete.  In order to get the path of the actual DLL, the POC code will be modified to call GetModuleHandleEx(), passing it the memory address of a function within the DLL.  This API will return a handle to the DLL, which can then be passed to GetModuleFileName() as in the original in order to retrieve the full path of the DLL for use in the rest of the code.  Example code is shown below:

![image](https://user-images.githubusercontent.com/91164728/164996799-c6fe6637-c0a8-4fae-bbf5-5c30369ed5ea.png)

Making self-deletion optional as was done in the exe format is less straightforward in a DLL; a solution I came up with was to simply provide multiple entry points for the DLL, one of which calls the self-deletion function and another of which does not.  This can be played with and fleshed out more if needed.

The POC provided for the self-deletion capability is identical to the operational implementation; the debugging lines were removed from the POC and functions collapsed into a single one, however it would be trivial to undo these changes.

## Closing thoughts

Thank you to all those who took the time to read what became a very lengthy writeup of two weeks or so worth of work.  There were a lot of issues that had to be dealt with that didn't make it into this post (porting all of the above to both LI and RSI shellcode runners, in exe and dll format, and successfully compiling to both x86 and x64).  I learned a lot about processes, memory, and C programming and ended up with some pretty cool bonus features for payloads along the way.  Hopefully this information was useful and helps others implement similar features in their work. 

The POC's provided, as was addressed in each individual section, are generally parsed down and not fully fleshed out. This is intentional to avoid providing completely weaponized code so that should someone want to use these techniques they are required to do a little work themselves so as to better understand it.
