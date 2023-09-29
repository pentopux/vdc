@echo off

echo "[+] Checking Administrative privileges ..."

net session >nul 2>&1

if %errorLevel% == 0 (
	echo Running as administrator
) else (
	echo Administrative privileges are needed
	exit
)

echo "[+] Installing Necessery Files..."

if exist "psloggedon.exe" (
	echo "[+] PsLoggedOn Already Installed"
) else (
	echo "[+] Installing PsLoggedOn"
	powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/PsLoggedon.exe -OutFile psloggedon.exe
)

if exist "logonsessions.exe" (
	echo "[+] LogonSessions Already Installed"
) else (
	echo "[+] Installing LogonSessions"
	powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/logonsessions.exe -OutFile logonsessions.exe
)

if exist "pslist.exe" (
	echo "[+] PsList Already Installed"
) else (
	echo "[+] Installing PsList"
	powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/pslist.exe -OutFile pslist.exe
)

if exist "DumpIt.exe" (
	echo "[+] DumpIt Already Installed"
) else (
	echo "[+] Installing DumpIt"
	powershell.exe Invoke-WebRequest -Uri https://raw.githubusercontent.com/thimbleweed/All-In-USB/master/utilities/DumpIt/DumpIt.exe -OutFile DumpIt.exe
)


if exist "psloglist.exe" (
	echo "[+] PsLogList Already Installed"
) else (
	echo "[+] Installing PsLogList"
	powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/psloglist.exe -OutFile psloglist.exe
)

if exist "psservice.exe" (
	echo "[+] PsService Already Installed"
) else (
	echo "[+] Installing PsService"
	powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/PsService.exe -OutFile psservice.exe
)

if exist "listdlls.exe" (
	echo "[+] ListDLLs Already Installed"
) else (
	echo "[+] Installing ListDLLs"
	powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/listdlls.exe -OutFile listdlls.exe
)


if exist "handle.exe" (
	echo "[+] Handle Already Installed"
) else (
	echo "[+] Installing Handle"
	powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/handle.exe -OutFile handle.exe
)

echo "[+] Collecting Time&Date"

date /t >> log.txt
time /t >> log.txt


echo "[+] Machine Info"

wmic os get caption >> log.txt
wmic cpu get Name >> log.txt
wmic path Win32_videoController get name >> log.txt
wmic computersystem get totalphysicalmemory >> log.txt
wmic csproduct get UUID >> log.txt
echo %COMPUTERNAME% >> log.txt

echo "[+] Clipboard Text"

powershell.exe Get-ClipBoard >> log.txt

echo "[+] Collecting Network Data"
netstat -an >> log.txt
netstat -r >> log.txt
ipconfig /all >> log.txt

echo "[+] ARP Cache History"

arp -a >> log.txt

echo "[+] Scheduled Tasks"

schtasks.exe >> log.txt

echo "[+] Remote Logged In Users"

net sessions >> log.txt
logonsessions.exe >> log.txt



echo "[+] Collecting User&Logs Data"
wmic useraccount list full >> log.txt
psloggedon.exe >> log.txt
pslist.exe /d /m /x >> log.txt
psloglist.exe -x >> log.txt
PsService.exe >> log.txt
net user >> log.txt
net localgroup administrators >> log.txt
net localgroup "Remote Management Users" >> log.txt


echo "[+] Collecting In Use DLLs"

listdlls.exe >> log.txt


echo "[+] Listing Open Files"

handle.exe >> log.txt

echo "[+] Collecting Excluded IPAddresses"

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses" >> log.txt

echo "[+] Collecting Excluded Extensions"

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" >> log.txt

echo "[+] Collecting Excluded Paths"

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" >> log.txt

echo "[+] Collecting Excluded Processes"

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" >> log.txt

echo "[+] Collecting Excluded Temporary Paths"

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths" >> log.txt

echo "[+] Collecting Startup Files"

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" >> log.txt

echo "[+] System Information"

systeminfo >> log.txt


echo "[+] USB Device History"

wmic path Win32_USBControllerDevice get Dependent, Antecedent >> log.txt

echo "[+] Getting PowerShell History"

powershell.exe Get-History >> log.txt

echo "[+] Boot Configuration"

bdedit.exe >> log.txt

echo "[+] Getting Saved Wireless Networks"

netsh wlan show profiles >> log.txt

echo "[+] Getting Installed Applications"

powershell.exe Get-WmiObject -Class Win32_Product >> log.txt

echo "[+] Dumping Memory ..."
echo "[+] Type 'y' if asked"
DumpIt.exe


