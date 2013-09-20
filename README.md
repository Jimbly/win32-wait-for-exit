win32-wait-for-exit
===================

Simple utility to launch a Win32 process and wait until all child processes have exited, with elevation if required.

This is handy for general shell scripting if you want to wait for a process to finish what it is doing, but the initially
spawned process exits immediately (possibly because it re-launches itself with elevated priviledges).

Tested on Windows 7, should work on other varieties.

Installation
------------
Download the executable from:  
https://github.com/Jimbly/win32-wait-for-exit/raw/master/bin/LaunchAndWait.exe  
Or clone the source and build with Visual Studio

Usage
-----
Set the working directory to where you want to run the child process, run
```
LaunchAndWait.exe otherprog.exe otherprogargs ...
```

Steam Example Usage
-------------------
Sometimes, though rarely, I play a game which is not on Steam.  I do, however, want my friends to know
I'm playing this game, so they can join in.  Unfortunately some of them (especially if they have their
own patching mechanism) don't play well with Steam and exit immedaitely, showing me as not in a game in
Steam.

For an example, I have a shortcut to MechWarrior Online on my desktop, and I want to run this through
Steam.  Examining the properties on the shortcut, it has a Target of
```
"C:\Games\MechWarrior Online\Bin32\MechWarriorOnline.exe"
```
And "Start in" set to
```
"C:\Games\MechWarrior Online\Bin32\"
```
I download LaunchAndWaith.exe to C:\bin, I leave the "Start in" set at what it is, and change the Target to 
```
"C:\bin\LaunchAndWait.exe" MechWarriorOnline.exe
```
Now, launching that shortcut (after a privilege elevation prompt), launches MWO and does not exit the first
process until I exit MWO, great!

Finally to get this into Steam, in the Library view, choose Games | Add a Non-Steam Game to My Library...,
and the list should populate with a ton of stuff.  One of them is MechWarrior Online, with "Location"
listed as "C:\bin" (where I installed LaunchAndWait.exe).  I choose that one, click Add Selected Programs.
Unfortunately, Steam is slightly confused, and lost both the command line parameters and the "Start in"
from the original shortcut!  So, I right click on the new entry in my Library, choose Properties, fix the
Target to be the same as above (just have to add " MechWarriorOnline.exe" to the end), and completely
replace the Start In to the same as above ("C:\Games\MechWarrior Online\Bin32\").


Caveats
-------
The method this is using may not work if a process launches a child and the child launches a grand-child, and the
intervening child is not around long enough (100ms) for this program to notice.
