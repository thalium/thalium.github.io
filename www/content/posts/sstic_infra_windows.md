# Introduction

This post aims to present how to easily setup a lightweight secure user pwning environment for Windows. From your binary challenge communicating with stdin/stdout, this environment leads to have a multi-client broker listening on a socket, redirecting it to the IO of your binary, and executing it in a jail. This environment is mainly based on the project [AppJaillauncher-rs](https://github.com/trailofbits/AppJailLauncher-rs) from trailofbits, with some security fixes and some tips to easily setup the RW rights to the system files from the jail.

The code of the modified AppJailLauncher-rs is available [here](https://github.com/challengeSSTIC2021/appjaillauncher-rs) and the code of the pwn user windows 10 challenge is available [here](https://github.com/challengeSSTIC2021/Step2_challenge).


## Context 

A Thalium Team's member participates to the conception of the [SSTIC challenge 2021](https://www.sstic.org/2021/challenge_en/). [SSTIC](https://www.sstic.org/) is one of the most important French cybersecurity conference that is organized every year since 2003. Since 2009 a challenge is proposed several weeks before the start of the conference. This challenge is usually relatively hard/long to solve, this year, b2xiao, the fastest player tooks more than 3 days to solve it. The challenge was split into 5 parts, the Thalium's member contribution was on the step 2. You can find other steps of the challenge on the [GitHub Page](https://github.com/challengeSSTIC2021) of the challenge 

This second step was a userland pwn challenge running on a Windows 10 operating system. After reversing the binary and finding the vulnerabilities, the players obtained a heap leak and a RW primitive leading to a RCE. For more information, about solving the challenge you can read the solutions of the participants of the challenge, available on [this page](https://www.sstic.org/2021/challenge/).


## Requirements

The specifications can be listed as below : 

* Limited resources, the proposed machine to use for the remote was [16GO DDR3, 2*1 To Storage, Intel® Xeon E3 1220v2 (4 cores)](https://www.scaleway.com/fr/dedibox/start/start-1-l/). This machine needs to also host the remote infrastructure for other steps, and is running with KVM;
* As this challenge is the second step and the first is an easy step, it is possible than dozens of challengers connects to this challenge simultaneously;
* As it is a CTF challenge, it is needed that players can not interfere with other players once they get an RCE;
* Players can not make network connections once a RCE is obtained;
* Be somewhere resistant to *script-kiddies* tentative of DOS;
* Preferable that the binary challenge communicates with stdin/stdout in order to not handle network connection;
* Private temporary RW folder for each participant. This requirement is related to the context of the binary challenge;
* Players can read a "big" file on a user Desktop in order to access the next steps of the challenge.



## Considered solutions

The two following solutions were considered :

1. Docker with one of the [windows/servercore/nanoserver base OS images](https://hub.docker.com/_/microsoft-windows-base-os-images) + [socat](https://sourceforge.net/projects/unix-utils/files/socat/1.7.3.2/)/xinetd cygwin to redirect socket to stdin/stdout

2. [AppJaillauncher-rs](https://github.com/trailofbits/AppJailLauncher-rs)

None of these solutions were previously experimented and the lack of remaining time implies that it was not possible to compare the two solutions. 

The main drawback of the docker solution is that it seems a little bit expensive in memory, CPU and storage usage at a "high-scale level" compared to the resources available. Though, nanoserver seems to be very [light](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements). 

The main drawbacks of the AppJailLauncher solution is that (i) the security of the solution has to be checked, even if it has already been used by other people; (ii) customize some configuration of the environment to have a RW private folder for each participant.

During the conception of the challenge, the point that seems the most important was that the remote server will still be alive after a "massive arrival" of players on the step 2. For this reason, the AppJailLauncher solution was selected. Also it seemed easier to test this solution as you can work with it on your laptop easily.

Checking if the Docker solution was better than the AppJailLauncher is left as an exercise to the reader :).


# AppJailLauncher-rs

As described on the GitHub page of the project : 

AppJailLauncher is akin to a simple version of xinetd for Windows but with sandboxing enabled for the spawned child processes. The sandboxing is accomplished via [AppContainers](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation). This project is a rewrite of an earlier version in C.

For more information about the AppContainer sandboxing mechanism you can read this [page](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation).

## Security problems and their mitigations


### Killing processes

After auditing the AppJailLauncher project, it turns out that all the processes of the challengers are spawned with the same AppContainerProfile. This could lead to a kind of DoS if a malicious challenger is present. Indeed, once a player obtains its remote code execution, he can try to continuously kill all the processes containing the name of the binary challenge. As the duration of the script exploiting the challenge is of several seconds, the malicious player can prevent other people to solve the challenge with a ratio of 100%.

In order to avoid this kind of DoS, AppJailLauncher has been modified. In the Thalium's version, each connection creates dynamically a new AppContainerProfile that is deleted 10 minutes after the connection.

### DoS by huge resource consumption

The AppJailLauncher project does not provide any mechanism to prevent an excessive RAM or process usage. They propose to add a function inside the challenge source code in order to kill the process after a certain amount of time. The problem with this solution is that after the player obtained a RCE he can kill the thread responsible of this task or he can also spawn other process to bypass this limitation.

Windows provides a mechanism to add this kind of limitation, called Job. In the Thalium's version, a job is set to the spawned process. This job limits the number of processes that can be launched, the timelife and also the maximum memory usage. All these information are configurable with the command line as described in the usage command of AppJailLauncher.

During the SSTIC competition, the limitations were quite restricted, 2 minutes, 100 MB of RAM, 2 parallel processes.

There is still one problem that was not addressed, a DoS by writing a lot of data to the disk. This was quite mitigated by the fact that the only one folder that was writable for each player was removed 10 minutes after its creation. 


## Feature needed

Due to context of the challenge, players need to be able to write to the disk. This folder needs to be private for each player, as the files created are used to exploit the binary. As with the modification of AppJailLauncher, each process is nows spawned with a different AppContainerProfile, it is enough to create a folder and add the RW rights for the SID of the AppContainerProfile.

The duration of these private folders is 10 minutes. In order to be able to reuse this folder during its lifetime, the AppJailLauncher project has been modified and gives to the user a UID when it creates the private folder. For the following connections, the user can give its UID and it will be used to associate the previously created folder to the player. In order to avoid players bruteforcing this UID, it was hashed together with the IP address of the player, and a secret string to generate the folder name.


## Access to the Desktop file 

After obtaining a remote code execution, players need to exfiltrate a file that is present on the Desktop of a user of the system. As all the processes are running under different AppContainerProfile, it seems to be a bad idea to add the rights dynamically for each spawned process. 
Indeed, it exists an SID corresponding to `APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES` that will be effective for all AppContainerProfile. This SID is S-1-15-2-2. The RX rights are needed in order to allow the players to list the folders from C:\ to the file on the Desktop.


## Commands to execute

Command line to add the RW rights to the file on the Desktop of the user, only needed to be executed once per machine :

```
ICACLS "C:\Users" /grant "*S-1-15-2-2:(R,RX)"
ICACLS "C:\Users\Challenge" /grant "*S-1-15-2-2:(R,RX)"
ICACLS "C:\Users\Challenge\Desktop" /grant "*S-1-15-2-2:(R,RX)"
ICACLS "C:\Users\Challenge\Desktop\DRM.zip" /grant "*S-1-15-2-2:(R,RX)"
```



Command line to execute AppJailLauncher : 

```
 C:\Tools\appjaillauncher-rs.exe run --foldermazes "C:\users\challenge\\mazes" "C:\Tools\SSTIC.exe"
```

"C:\Tools\SSTIC.exe" argument is the binary that will be executed when a challenger connects to the port where appjaillauncher listen.

`Foldermazes` parameter is the folder that will contain the private folders. It is needed that this folder exists before running appjaillauncher.

More parameters can be defined, as the port where the program listens, the job limitations (time, memory, number of processes), etc.



# Problems to investigate 

## ASLR

## cmd Vs Powershell

## DOS Powershell

## Powershell arguments



# Future work

As the time was constrained for the deployment of the infrastructure some things could be improved : 

* As it was the first time for the author to read and write Rust, the written code could be slightly improved.
* It seems that some implementations of netcat are not compatible with the functionality that ask the UID of the player. The program will still answer that it needs 64 chars exactly even if the player inputs 64 chars. The problem is certainly due to the end of line character. 
* Add some statistics of usage (total number of connections, number of crashes, number of connections alive, etc.)

