@echo off

systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> info.out

hostname >> info.out

echo %username% >> info.out

net users >> info.out

ipconfig /all >> info.out

route print >> info.out

arp -A >> info.out

netstat -ano >> info.out

netsh firewall show state >> info.out

netsh firewall show config >> info.out

schtask /query /fo LIST /v >> info.out

tasklist /SVC >> info.out

net start >> info.out

:: 3rd party driver query
DRIVERQUERY


:: WMIC enumeration
for /f "delims=" %%A in ('dir /s /b %WINDIR%\system32\*htable.xsl') do set "var=%%A"

wmic process get CSName,Description,ExecutablePath,ProcessId /format:"%var%" >> out.html
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:"%var%" >> out.html
wmic USERACCOUNT list full /format:"%var%" >> out.html
wmic group list full /format:"%var%" >> out.html
wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:"%var%" >> out.html
wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:"%var%" >> out.html
wmic netuse list full /format:"%var%" >> out.html
wmic qfe get Caption,Description,HotFixID,InstalledOn /format:"%var%" >> out.html
wmic startup get Caption,Command,Location,User /format:"%var%" >> out.html
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:"%var%" >> out.html
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:"%var%" >> out.html
wmic Timezone get DaylightName,Description,StandardName /format:"%var%" >> out.html


:: "AlwaysInstallElevated", if this setting is enabled it allows users of any privilege level to install *.msi files as NT AUTHORITY\SYSTEM

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> registry.out
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> registry.out

:: keyword search
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

:: Windows service manager operations
sc qc Spooler

:: List all service privilege requirements
accesschk.exe /accepteula
accesschk.exe -ucqv *

