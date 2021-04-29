---
title: "HackTheBox Cyber Apocalypse 2021"
categories: [Writeups]
layout: post 
---

# HackTheBox Cyber Apocalypse 2021 Writeups

## Team Placing: 210 / 2735

This was honestly one of my favorite CTFs for the Spring semester despite playing solo for most of the week (finals were upcoming). The forensics challenges were a ton of fun and very interesting to me, and I also enjoyed a lot of the web exploitation challenges.

## Categories
* ### Forensics
    * #### [Oldest trick in the book](#challenges-oldest-trick-in-the-book)
    * More writeups soon!

-------------------------------------------------------------------------------

### Challenge: Oldest trick in the book
### Category: Forensics

## Description:

![](Oldest%20trick%20in%20the%20book%20Writeup.001.png)

## Walkthrough:

Opening up the provided pcap file, named `older_trick.pcap`, we're presented with what seems like fairly normal TCP traffic:

![](Oldest%20trick%20in%20the%20book%20Writeup.002.png)

Nothing is particularly out of the ordinary, and most of it is TLS encrypted. However, if we continue scrolling through the traffic we notice that there seems to be quite a lot of `ICMP` ping packets:

![](Oldest%20trick%20in%20the%20book%20Writeup.003.png)

Interesting.. These ping reply and request packets make up over 50% of the entire packet capture, which is definitely suspicious.

It is fairly common for attackers to use protocols like ICMP for [C2 communication](https://attack.mitre.org/techniques/T1095/) which could also be used for [Data Exfiltration](https://attack.mitre.org/techniques/T1041/) so this could potentially be the avenue the attacker used to steal data. 

With that in mind, let's use the `icmp` filter to look at only ICMP traffic and let's take a look at the first ping request packet:

![](Oldest%20trick%20in%20the%20book%20Writeup.004.png)

One of the first things I noticed was the `PK` in the data field. `PK` is the file signature for a ZIP file so it is very strange that it is appearing in an ICMP packet. If you continue analyzing the other ping request packets, you will find other interesting strings such as `addons.json` and `storage.sqlite` which are most likely some of the files within this ZIP file.

Cool, so we have a decent idea of what's going on. There's a few different ways you could continue from here such as using [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) to extract the data field but during the competition I opted for just parsing a simple CSV file. 

Since the reply packets contain the same data as the request packets, I first filtered by the requests packets: `icmp.type == 8`

Then I applied the `Data` section of the packet as a column which gave me something that looked like this:

![](Oldest%20trick%20in%20the%20book%20Writeup.005.png)

Finally, I exported the packets as a CSV by going to `File -> Export Packet Dissections -> As CSV...` This created a CSV file named `data.csv` which contained the `Data` section as a column in hex.

Great, now we just need to parse this CSV by decoding the hex data. I crafted a Python script to do this for me:

```python
# open the data.csv file
with open('data.csv', 'r') as f:

    # read all of the lines
    lines = f.readlines()

    # for each line
    for line in lines:
        
        # Grab the column with the hex data [6] and slice
        # off that which isn't part of the ZIP file [17:-10]. Then
        # convert from hex to bytes
        line = bytes.fromhex((line.split(',')[6][17:-10]))

        # open a file named sus.zip in a: append and b: bytes mode
        with open('sus.zip', 'ab') as f:

            # write the bytes to the file
            f.write(line)
```

Running the script we do indeed get a valid ZIP file:

```bash
$ file sus.zip

sus.zip: Zip archive data, at least v2.0 to extract
```

Awesome, let's unzip the file and take a look at what we get:

![](Oldest%20trick%20in%20the%20book%20Writeup.006.png)

Interesting, this looks like a Mozilla Firefox user profile which we can tell by the `MOZLZ4` extension in some of the files as well as just by googling some of the file names.

One thing about browser files is that they often store login credentials if a user opts to save them. With this in the mind, the `logins.json` file looks pretty interesting so let's take a look:

```json
"nextId":2,"logins":[{"id":1,"hostname":"https://rabbitmq.makelarid.es","httpRealm":null,"formSubmitURL":"https://rabbitmq.makelarid.es","usernameField":"username","passwordField":"password","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECMeab8LuajLlBAixWaWDdSvdNg==","encryptedPassword":"MEoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECGKAhjI0M93wBCDzNVgOAQ9Qn77aRp791mOjsyTjoAINAym/9+wmwdI/hQ==","guid":"{aed76f86-ae6a-4ef5-b413-be3769875b0f}","encType":1,"timeCreated":1618368893810,"timeLastUsed":1618368893810,"timePasswordChanged":1618368893810,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}
```

So it looks like we have credentials of this user for the site, `https://rabbitmq.makelarid.es`, but the credentials are encrypted. A simple google search of "Firefox decrypt passwords" introduced me to a tool called [`firefox_decrypt`](https://github.com/unode/firefox_decrypt).

Running the `firefox_decrypt.py` script we successfully decrypt the username and password and get the flag:

```bash
$ python3 firefox_decrypt.py ../sus/fini/
2021-04-29 03:34:13,795 - WARNING - profile.ini not found in ../sus/fini/
2021-04-29 03:34:13,797 - WARNING - Continuing and assuming '../sus/fini/' is a profile location

Website:   https://rabbitmq.makelarid.es
Username: 'Frank_B'
Password: 'CHTB{long_time_no_s33_icmp}'
```

Nice, we successfully identified what was stolen during the data breach! This challenge was a ton of fun!

### Flag: CHTB{long_time_no_s33_icmp}

----------------------------------------------------------------------------------