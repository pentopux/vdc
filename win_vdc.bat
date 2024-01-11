@echo off
setlocal enabledelayedexpansion

REM Check Administrative privileges
echo "[+] Checking Administrative privileges ..."
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Administrative privileges are needed
    exit /b 1
)

REM Install Necessary Files
echo "[+] Installing Necessary Files..."
set tools=("psloggedon.exe" "logonsessions.exe" "pslist.exe" "DumpIt.exe" "psloglist.exe" "psservice.exe" "listdlls.exe" "handle.exe")
for %%i in %tools% do (
    if not exist %%i (
        echo "[+] Installing %%~nxi"
        powershell.exe Invoke-WebRequest -Uri https://live.sysinternals.com/%%~nxi -OutFile %%i
    ) else (
        echo "[+] %%~nxi Already Installed"
    )
)

REM Collect Time & Date
echo "[+] Collecting Time & Date" >> log.txt
date /t >> log.txt
time /t >> log.txt

REM Collect Machine Info
echo "[+] Machine Info" >> log.txt
wmic os get caption >> log.txt
wmic cpu get Name >> log.txt
wmic path Win32_videoController get name >> log.txt
wmic computersystem get totalphysicalmemory >> log.txt
wmic csproduct get UUID >> log.txt
echo %COMPUTERNAME% >> log.txt

REM Collect Clipboard Text
echo "[+] Clipboard Text" >> log.txt
powershell.exe Get-Clipboard >> log.txt

REM Collect Network Data
echo "[+] Collecting Network Data" >> log.txt
netstat -an >> log.txt
netstat -r >> log.txt
ipconfig /all >> log.txt

REM Collect ARP Cache History
echo "[+] ARP Cache History" >> log.txt
arp -a >> log.txt

REM Collect Scheduled Tasks
echo "[+] Scheduled Tasks" >> log.txt
schtasks.exe >> log.txt

REM Collect Remote Logged In Users
echo "[+] Remote Logged In Users" >> log.txt
net sessions >> log.txt
logonsessions.exe >> log.txt

REM Collect User & Logs Data
echo "[+] Collecting User & Logs Data" >> log.txt
wmic useraccount list full >> log.txt
psloggedon.exe >> log.txt
pslist.exe /d /m /x >> log.txt
psloglist.exe -x >> log.txt
psservice.exe >> log.txt
net user >> log.txt
net localgroup administrators >> log.txt
net localgroup "Remote Management Users" >> log.txt

REM Collect In Use DLLs
echo "[+] Collecting In Use DLLs" >> log.txt
listdlls.exe >> log.txt

REM List Open Files
echo "[+] Listing Open Files" >> log.txt
handle.exe >> log.txt

REM Collect Excluded Registry Entries
echo "[+] Collecting Excluded Registry Entries" >> log.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions" >> log.txt

REM Collect Startup Files
echo "[+] Collecting Startup Files" >> log.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" >> log.txt

REM Collect System Information
echo "[+] System Information" >> log.txt
systeminfo >> log.txt

REM Collect USB Device History
echo "[+] USB Device History" >> log.txt
wmic path Win32_USBControllerDevice get Dependent, Antecedent >> log.txt

REM Collect PowerShell History
echo "[+] Getting PowerShell History" >> log.txt
powershell.exe Get-History >> log.txt

REM Collect Boot Configuration
echo "[+] Boot Configuration" >> log.txt
bcdedit.exe >> log.txt

REM Collect Saved Wireless Networks
echo "[+] Getting Saved Wireless Networks" >> log.txt
netsh wlan show profiles >> log.txt

REM Collect Installed Applications
echo "[+] Getting Installed Applications" >> log.txt
powershell.exe Get-WmiObject -Class Win32_Product >> log.txt

REM Collect Security Events
echo "[+] Collecting Security Events" >> log.txt
wevtutil qe Security /c:1 /f:text >> log.txt

REM Dump Memory
echo "[+] Dumping Memory ..." >> log.txt
echo "[+] Type 'y' if asked"
DumpIt.exe

endlocal
