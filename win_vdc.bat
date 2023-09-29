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

echo "[+] Clipboard Text"

powershell.exe Get-ClipBoard >> log.txt

echo "[+] Collecting Network Data"
netstat -an >> log.txt
netstat -r >> log.txt
ipconfig /all >> log.txt


echo "[+] Scheduled Tasks"

schtasks.exe >> log.txt

echo "[+] Remote Logged In Users"

net sessions >> log.txt
logonsessions.exe >> log.txt



echo "[+] Collecting User&Logs Data"

psloggedon.exe >> log.txt
pslist.exe /d /m /x >> log.txt
psloglist.exe -x >> log.txt
PsService.exe >> log.txt
net user >> log.txt
net localgroup administrators >> log.txt
net localgroup "Remote Management Users" >> log.txt


echo "[+] Collecting In Use DLLs"

listdlls.exe >> log.txt


echo "[+] Collecting Handle Informations"

handle.exe >> log.txt

