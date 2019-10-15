# goWMIExec

Based on https://github.com/checkymander/Sharp-WMIExec/blob/master/Sharp-InvokeWMIExec/Program.cs

Which is based on  https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1


Currently a (functional) work in progress. 

Features:
- Can authenticate using hash-only
- Don't need to install impacket
- Native go and byte bashing on TCP sockets, no need to run on Windows

Limitations:
- Lots of static bytes. Future development will turn these into proper structures, and hopefully allow for other DCOM/COM methods to be used
- Long commands won't work. Make them shorter, or create a PR to implement fragments in the Exec method.

Example:
`goWMIExec -target "172.16.50.202:135" -username "vagrant" -hash "e02bc503339d51f71d913c245d35b50b" -command 'C:\Windows\system32\cmd.exe /c echo test > C:\test.txt'`