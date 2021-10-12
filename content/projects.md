+++
author = "Kevin Goyette"
title = ""
date = "2021-09-10"
description = "Here's a presentation of the projects I've worked on."
tags = [
    "projects"
]
categories = [
    "projects"
]
series = ["My skills"]
aliases = ["projects"]
+++


# kevin@blog:\~$ ls projects


{{< rawhtml >}}
<div style="margin-top: 7rem;"></div>
{{< /rawhtml >}}
## Filesystem API Monitor
I developed a windows filesystem API monitor that is able to trace any access to any files on the system including [named pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes).
I originally built this application to find where an application was extracting its files. 
The application is written in C and uses [function hooks](https://en.wikipedia.org/wiki/Hooking) in order to achieve its goal. 

[I wrote an in-depth post about this project.](/posts/fs_capture/)



{{< rawhtml >}}
<div style="margin-top: 7rem;"></div>
{{< /rawhtml >}}
## Screen capture and upload service(W.I.P.)
I'm currently working on a screen capture application that let's you upload 
it to my server or as a self-hosted service. 




