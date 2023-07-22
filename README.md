# WinForensic


The script obtains the following information:
1.	Events from the event viewer (System, Application and Security).
2.  User and account information:
    - Local system users.
    - User profiles and active login sessions.
    - Local groups and members of the "Administrators" group.
    - Creating, modifying and deleting users.
    - Successful and failed logins
    - Local and domain group member enumeration events.
3.	Network information:
    - Local and remote TCP connections.
    - Network routes and network adapters.
4.	System information:
    - Data about the system, such as machine name, domain, etc.
    - Hotfixes installed on the system.
    - Gets the contents of the hosts file.
    - list of programs installed on the system
5.	Search for potentially suspicious activities:
    - Checks the "Run" and "RunOnce" registry keys for programs that start automatically and are likely to gain persistence on the system.
    - Look for executable files and other suspicious types in the "AppData" and "Temp" folders.
