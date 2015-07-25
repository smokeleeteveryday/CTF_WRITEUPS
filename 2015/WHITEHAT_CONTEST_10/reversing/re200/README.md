# WhiteHat Contest 10: Re200

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| WhiteHat Contest 10 | Re200 | Reversing |    200 |

**Description:**
>*Flag = WhiteHat{SHA1(key)}*

----------
## Write-up
### First look

We are presented with a zip file containing a single windows executable `Re200.exe`. Running the file through TrID yields the following:

```
C:\ctf\whitehat_contest_10\re200>trid Re200.exe

TrID/32 - File Identifier v2.20 - (C) 2003-15 By M.Pontello
Definitions found:  5978
Analyzing...

Collecting data from file: Re200.exe
64.6% (.EXE) Win64 Executable (generic) (27646/36/4)
15.3% (.DLL) Win32 Dynamic Link Library (generic) (6578/25/2)
10.5% (.EXE) Win32 Executable (generic) (4508/7/1)
4.6% (.EXE) Generic Win/DOS Executable (2002/3)
4.6% (.EXE) DOS Executable Generic (2000/1)
```

Next, we run the windows sysinternals version of `strings` on the file:

```
C:\ctf\whitehat_contest_10\re200>strings -n 8 Re200.exe

Strings v2.51
Copyright (C) 1999-2013 Mark Russinovich
Sysinternals - www.sysinternals.com

!This program cannot be run in DOS mode.
bad allocation
bad allocation
V0hAdCFGbGFnPSg=
Q1RHTU5TUUdUKQ==
QUIyNDFBQw==
R2V0UHJvY0FkZHJlc3M=
TG9hZExpYnJhcnlB
VXNlcjMyLmRsbA==
bXN2Y3J0LmRsbA==
c2hsd2FwaS5kbGw=
cHJpbnRm
TWVzc2FnZUJveEE=
RmFpbCE=
U3VjY2VzcyE=
S2V5IE9LIQ==
S2V5IHdyb25nIQ==
U3RyQ21wVw==
U3RyQ3B5Vw==
bad allocation
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
s:\CTF\Win32Base\Release\Win32Base.pdb
(...)
```

We clearly see a bunch of base64 encoded strings embedded.

### Solving the challenge
To find the solution to this challenge, we first decode the base64 strings to find out what they represent. We quickly create this simple script to decode them:

```python3
import base64

encoded_strings = [
    'V0hAdCFGbGFnPSg=',
    'Q1RHTU5TUUdUKQ==',
    'QUIyNDFBQw==',
    'R2V0UHJvY0FkZHJlc3M=',
    'TG9hZExpYnJhcnlB',
    'VXNlcjMyLmRsbA==',
    'bXN2Y3J0LmRsbA==',
    'c2hsd2FwaS5kbGw=',
    'cHJpbnRm',
    'TWVzc2FnZUJveEE=',
    'RmFpbCE=',
    'U3VjY2VzcyE=',
    'S2V5IE9LIQ==',
    'S2V5IHdyb25nIQ==',
    'U3RyQ21wVw==',
    'U3RyQ3B5Vw=='
]

def decode(encoded):
    return base64.b64decode(encoded).decode()

for encoded_string in encoded_strings:
    print(encoded_string.ljust(24), ':', decode(encoded_string))
```

Running this presents us with the following output:

```
C:\ctf\whitehat_contest_10\re200>decode.py
V0hAdCFGbGFnPSg=         : WH@t!Flag=(
Q1RHTU5TUUdUKQ==         : CTGMNSQGT)
QUIyNDFBQw==             : AB241AC
R2V0UHJvY0FkZHJlc3M=     : GetProcAddress
TG9hZExpYnJhcnlB         : LoadLibraryA
VXNlcjMyLmRsbA==         : User32.dll
bXN2Y3J0LmRsbA==         : msvcrt.dll
c2hsd2FwaS5kbGw=         : shlwapi.dll
cHJpbnRm                 : printf
TWVzc2FnZUJveEE=         : MessageBoxA
RmFpbCE=                 : Fail!
U3VjY2VzcyE=             : Success!
S2V5IE9LIQ==             : Key OK!
S2V5IHdyb25nIQ==         : Key wrong!
U3RyQ21wVw==             : StrCmpW
U3RyQ3B5Vw==             : StrCpyW
```

The first couple of strings are to our interest, first we try the first two together, which make up `WH@t!Flag=(CTGMNSQGT)`.

```
C:\ctf\whitehat_contest_10\re200>Re200.exe WH@t!Flag=(CTGMNSQGT)
Key wrong!
```

Ok, this isn't our key, let's try adding third string to the equation making up a key `WH@t!Flag=(AB241ACCTGMNSQGT)`.

```
C:\ctf\whitehat_contest_10\re200>Re200.exe WH@t!Flag=(AB241ACCTGMNSQGT)
Key OK!
```

And we found our key!

### Solution
Rounding it all up, the SHA1 of the key resolves to `1ceeebacb946479997e13a289124ac080693c0bc` making the final solution:

> `WhiteHat{1ceeebacb946479997e13a289124ac080693c0bc}`
