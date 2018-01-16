
# jdss-cli-tools

<b>Remotely execute given JovianDSS command. Clone and iSCSI export and other commands to control JovianDSS remotely</b>
<br>Note:
Please enable the CLI access in GUI :
Setup -> Administrator setting -> CLI access
<br>

Show help:
	jdss-cli-tools.exe --help

EXAMPLES:

<br>1. Create Clone of iSCSI volume zvol00 from Pool-0 and attach to iSCSI target. Every time it runs, it will delete the clone created last run and re-create new one. So, the target exports most recent data every run.  The example is using default password and port.

	jdss-cli-tools.exe  clone Pool-0 zvol00  192.168.0.220

<br>2. Shutdown three JovianDSS servers using default port but non default password

	jdss-cli-tools.exe  --pswd password shutdown 192.168.0.220 192.168.0.221 192.168.0.222
<br>3. Reboot single DSS server

	jdss-cli-tools.exe  reboot 192.168.0.220

#
#After any modifications of source jdss-tools.py, run pyinstaller to create new jdss-tools.exe:

	C:\Python27>Scripts\pyinstaller.exe --onefile jdss-cli-tools.py
#
And try it:

	C:\Python27>dist\jdss-cli-tools.exe -h
NOTE:
In case of error: "msvcr100.dll missing ...",
download and install: Microsoft Visual C++ 2010 Redistributable Package (x86) vcredist_x86.exe
