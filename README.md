# Adblocker
A locally hosted DNS adblocker on the local network

# C commands
Run these in powershell in the Adblocker folder
## Compile
gcc -Wall -Wextra -g3 main.c adblocker.c -o output\adblocker.exe -lws2_32 
## Run 
.\output\adblocker.exe   

# Make trafic run through adblocker
Run this in any powershell terminal
## Start
PS C:\Windows\system32> Set-DnsClientServerAddress -InterfaceAlias "WiFi 2" -ServerAddresses 127.0.0.1
ipconfig /flushdns
## Stop
Set-DnsClientServerAddress -InterfaceAlias "WiFi 2" -ResetServerAddresses
ipconfig /flushdns