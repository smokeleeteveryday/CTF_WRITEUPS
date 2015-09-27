# Trend Micro CTF 2015: Analysis - Defensive 200

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| Trend Micro CTF 2015 | Analysis - Defensive 200 | Reversing |    200 |

**Description:**
>*Category: Analysis-defensive*
>
>*Points: 200*
>
>*Capture the flag by analyzing the file. (pass: TMCTF2015)*

----------
## Write-up

[We are given an archive](challenge/AnalyzeThis.zip) containing a Windows 32-bit Portable Executable (PE) binary:

```bash
$ file AnalyzeThis.exe
AnalyzeThis.exe; PE32 executable for MS Windows (GUI) Intel 80386 32-bit
```

We load up the binary in IDA and start by statically reverse-engineering the core functionality (renaming function names and variables as well) which gives us the following pseudo-code:

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  int result; // eax@2
  int portnum; // [sp+0h] [bp-10h]@5
  int bufLen; // [sp+4h] [bp-Ch]@1
  LPCSTR lpszServerName; // [sp+8h] [bp-8h]@5
  char *c2_buffer; // [sp+Ch] [bp-4h]@4

  bufLen = 4;
  if ( check_compname() )
  {
    if ( decrypt_mystery_buffer() && get_data_from_url((LPCSTR)(url_data + 4), (int)&c2_buffer, (int)&bufLen) )
    {
      if ( get_hostname_and_port(c2_buffer, bufLen, (int)&lpszServerName, (int)&portnum) )
      {
        do_core(lpszServerName, portnum);
        free((void *)lpszServerName);
      }
    }
    result = 0;
  }
  else
  {
    result = -1;
  }
  return result;
}
```

The main routine starts by calling the function which we renamed as *check_compname*:

```c
signed int check_compname()
{
  signed int v1; // [sp+0h] [bp-120h]@1
  DWORD nSize; // [sp+4h] [bp-11Ch]@1
  CHAR computername; // [sp+8h] [bp-118h]@1
  char v4; // [sp+9h] [bp-117h]@1
  char *encoded_name; // [sp+118h] [bp-8h]@1
  char *decoded_name; // [sp+11Ch] [bp-4h]@1

  v1 = 0;
  computername = 0;
  memset(&v4, 0, 0x103u);
  encoded_name = "544e45574a3736383d365a4e";
  nSize = 260;
  GetComputerNameA(&computername, &nSize);
  decoded_name = (char *)decode_string(encoded_name);
  if ( !strcmp(&computername, decoded_name) )
    v1 = 1;
  free(decoded_name);
  return v1;
}
```

This function retrieves the local computer name and compares it against the decoded result of *"544e45574a3736383d365a4e"*. The *decode_string* function can be written in python as:

```python
def decode_string(a1):
  v4 = len(a1)
  v5 = 48
  v6 = 120
  v11 = ""
  if(v4 % 2 == 0):
    for i in xrange(v4 >> 1):
      v7 = a1[2*i]
      v8 = a1[2*i + 1]
      s = chr(48)+chr(120)+a1[2*i]+a1[2*i+1]
      v1 = int(s, 16)
      v11 += "%c" % (v1-i)

  return v11
```

Which gives us the target PC name of *"TMCTF2015-PC"*. If the executable is executed on a PC bearing this name the function *decrypt_myster_buffer* is executed which retrieves the computer name and feeds it to a sequence of routines manipulating an (as of yet) 'mystery buffer'. The decryption functionality looks as follows:

```c
int __cdecl decryption_routine(int key, __int16 keylen, int ciphertext, unsigned __int16 ciphertext_len)
{
  char keystream; // [sp+0h] [bp-110h]@1

  func1(key, keylen, (int)&keystream);
  return func2(ciphertext, ciphertext_len, (int)&keystream);
}

int __cdecl func1(int a1, __int16 a2, int a3)
{
  int result; // eax@4
  char v4; // ST0A_1@6
  unsigned __int8 v5; // [sp+Bh] [bp-9h]@1
  unsigned __int16 i; // [sp+Ch] [bp-8h]@1
  unsigned __int16 j; // [sp+Ch] [bp-8h]@4
  unsigned __int8 v8; // [sp+13h] [bp-1h]@1

  v8 = 0;
  v5 = 0;
  *(_BYTE *)(a3 + 256) = 0;
  *(_BYTE *)(a3 + 257) = 0;
  for ( i = 0; (signed int)i < 256; ++i )
    *(_BYTE *)(a3 + i) = i;
  result = 0;
  for ( j = 0; (signed int)j < 256; ++j )
  {
    v5 += *(_BYTE *)(a3 + j) + *(_BYTE *)(a1 + v8);
    v4 = *(_BYTE *)(a3 + j);
    *(_BYTE *)(a3 + j) = *(_BYTE *)(a3 + v5);
    result = v5;
    *(_BYTE *)(a3 + v5) = v4;
    LOBYTE(result) = v8++ + 1;
    if ( v8 == a2 )
      v8 = 0;
  }
  return result;
}

int __cdecl func2(int a1, unsigned int a2, int a3)
{
  char v3; // ST0D_1@3
  int result; // eax@4
  unsigned int i; // [sp+4h] [bp-Ch]@1
  unsigned __int8 v6; // [sp+Eh] [bp-2h]@1
  unsigned __int8 v7; // [sp+Fh] [bp-1h]@1

  v6 = *(_BYTE *)(a3 + 256);
  v7 = *(_BYTE *)(a3 + 257);
  for ( i = 0; i < a2; ++i )
  {
    ++v6;
    v7 += *(_BYTE *)(a3 + v6);
    v3 = *(_BYTE *)(a3 + v6);
    *(_BYTE *)(a3 + v6) = *(_BYTE *)(a3 + v7);
    *(_BYTE *)(a3 + v7) = v3;
    *(_BYTE *)(i + a1) ^= *(_BYTE *)(a3 + (unsigned __int8)(*(_BYTE *)(a3 + v7) + *(_BYTE *)(a3 + v6)));
  }
  *(_BYTE *)(a3 + 256) = v6;
  result = a3;
  *(_BYTE *)(a3 + 257) = v7;
  return result;
}
```

Inspection of the above routines reveals the algorithm to be RC4 (with *func1* being the RC4 key scheduling algorithm and *func2* being the Pseudo-Random Number Generator (PRNG) that generates RC4's keystream) thus revealing *decrypt_mystery_buffer* to work as follows: 

```c
signed int decrypt_mystery_buffer()
{
  __int16 cnamelen; // ax@2
  signed int v2; // [sp+0h] [bp-118h]@1
  DWORD nSize; // [sp+4h] [bp-114h]@1
  CHAR computername; // [sp+8h] [bp-110h]@1
  char v5; // [sp+9h] [bp-10Fh]@1

  v2 = 0;
  computername = 0;
  memset(&v5, 0, 0x103u);
  nSize = 260;
  if ( !url_data )
  {
    GetComputerNameA(&computername, &nSize);
    cnamelen = strlen(&computername);
    do_rc4_decrypt((int)&computername, cnamelen, (int)&mysterybuffer, 0x1CCu);
    url_data = (int)&mysterybuffer;
    if ( mysterybuffer == 0x35313032 )          // if(mysterbuffer[:4] == "2015")
      v2 = 1;
  }
  return v2;
}
```

So we decrypt the myster buffer using RC4 with the key "TMCTF2015-PC" which yields the following buffer:

```
2015http://ctfquest.trendmicro.co.jp:13106/126ac9f6149081eb0e97c2e939eaad52/top.html                                                <font color="#FEFEFE">
                                    </font>
                    /e45c2dc8d9e5b215ea141f2f609100f9/notify.php
    TMCTF2015-13106                                                 `Ω      key.bin
```

The next function executed is *get_data_from_url*:

```c
int __cdecl get_data_from_url(LPCSTR url, int buffer, int bytesRead)
{
  void *v3; // ST1C_4@1
  signed int v5; // [sp+4h] [bp-124h]@1
  void *lpBuffer; // [sp+8h] [bp-120h]@3
  HANDLE hFile; // [sp+Ch] [bp-11Ch]@4
  DWORD nNumberOfBytesToRead; // [sp+10h] [bp-118h]@2
  CHAR downloadpath; // [sp+18h] [bp-110h]@1
  DWORD NumberOfBytesRead; // [sp+124h] [bp-4h]@5

  v5 = 0;
  *(_DWORD *)buffer = 0;
  *(_DWORD *)bytesRead = 0;
  GetTempPathA(0x104u, &downloadpath);
  v3 = decode_string("746e65776a3736383d377e787c");// tmctf2015.tmp
  _snprintf(&downloadpath, 0x104u, "%s%s", &downloadpath, v3);
  free(v3);
  if ( !URLDownloadToFileA(0, url, &downloadpath, 0, 0) )
  {
    nNumberOfBytesToRead = get_file_size(&downloadpath);
    if ( nNumberOfBytesToRead != -1 )
    {
      lpBuffer = malloc(nNumberOfBytesToRead);
      if ( lpBuffer )
      {
        hFile = CreateFileA(&downloadpath, 0x80000000, 0, 0, 3u, 0, 0);
        if ( hFile != (HANDLE)-1 )
        {
          ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &NumberOfBytesRead, 0);
          CloseHandle(hFile);
          *(_DWORD *)buffer = lpBuffer;
          *(_DWORD *)bytesRead = nNumberOfBytesToRead;
          v5 = 1;
        }
        if ( !v5 )
          free(lpBuffer);
      }
    }
  }
  return v5;
}
```

This function connects to *http://ctfquest.trendmicro.co.jp:13106/126ac9f6149081eb0e97c2e939eaad52/top.html*, reads the HTML and extracts (using function *get_hostname_and_port*) the first token between tags:

```html
<font color="#FEFEFE">...</font>
```

If we navigate to that URL we are presented with a decoy blogging site:

![alt site](site.png)

Which hides tokens in its HTML:

```html
<div class="post-text">
    Summer is hot. I do not like summer.
    <br><font color="#FEFEFE">6c706564706d757a7c8542434445</font>
  </div>
      </div>
      
      <div class="post-entry" id="2015092401">
  <div class="post-header">
    <span class="post-date">
      Posted On: Sep 24, 2015
    </span>
    <span class="post-title">
      <a name="winter">Winter</a>
    </span>
  </div>
  <div class="post-text">
    Winter is cold. I like winter.
    <br><font color="#FEFEFE">63756874796a797b367d7c707a717b78738381417784448188954b54504d4e</font>
  </div>
      </div>
      
      <div class="post-entry">
  <div class="post-header">
    <span class="post-date" id="2015092301">
      Posted On: Sep 23, 2015
    </span>
    <span class="post-title">
      <a name="my_first_post">My first post</a>
    </span>
  </div>
  <div class="post-text">
    Hello Blog!
    <br><font color="#FEFEFE">313339313433363539853b3d3f4143</font>
  </div>
      </div>
```

Decoding the tokens using the *decode_string* function yields the following:

```
localhost|8888
ctfquest.trendmicro.co.jp|19400
127.0.0.1|12345
```

Which are typical *servername|port* configuration entries for malware Command & Control servers.

The final function execute is *do_core*:

```c
void __cdecl do_core(LPCSTR lpszServerName, __int16 portnum)
{
  signed int dothing; // [sp+4h] [bp-11Ch]@1
  signed int status; // [sp+Ch] [bp-114h]@1
  int v4; // [sp+10h] [bp-110h]@7
  LPCVOID lpBuffer; // [sp+14h] [bp-10Ch]@13
  char Buffer; // [sp+18h] [bp-108h]@7
  char v7[254]; // [sp+1Ah] [bp-106h]@13
  char cmd; // [sp+11Fh] [bp-1h]@1

  dothing = 1;
  status = 0;
  cmd = 0;
  if ( lpszServerName && portnum )
  {
    while ( dothing )
    {
      if ( get_file_size((LPCSTR)(url_data + 396)) == 35 )// filesize("key.bin") == 35
      {
        ++*(_DWORD *)(url_data + 392);
        if ( !(*(_DWORD *)(url_data + 392) % 0xAu) )
          status = 1;
      }
      v4 = 256;
      if ( get_keyfile(lpszServerName, portnum, status, &Buffer, (int)&v4) )
      {
        if ( v4 )
        {
          cmd = extract_cmd((int)&Buffer, v4);
          switch ( cmd )
          {
            case 0x4B:                          // K
              lpBuffer = &v7[Buffer];
              write_key_bin(&v7[Buffer], v4 - (&v7[Buffer] - &Buffer));
              break;
            case 0x53:                          // S
              do_mutex_stuff();
              break;
            case 0x54:                          // T
              dothing = 0;
              break;
          }
        }
        status = 0;
        Sleep(*(_DWORD *)(url_data + 388));     // sleep(60000)
      }
    }
  }
}
```

This routine checks for the existence of "key.bin" on the machine and if it exists (and is exactly 35 bytes in size) increments a counter. If the counter is a multiple of 10 the *status* variable is set to 1. Next the *get_keyfile* function is executed which connects to the server and port extracted from the decoy blog and sets a particular cookie value (encoding the status variable) and user agent to retrieve a keyfile from the Command & Control server:

```
int __cdecl get_keyfile(LPCSTR lpszServerName, __int16 portnum, int status, LPVOID dstBuffer, int a5)
{
  HINTERNET hConnect; // [sp+0h] [bp-F4h]@2
  unsigned int v7; // [sp+4h] [bp-F0h]@1
  signed int v8; // [sp+8h] [bp-ECh]@1
  char getparams; // [sp+Ch] [bp-E8h]@1
  char v10; // [sp+Dh] [bp-E7h]@1
  char *cookieheader; // [sp+4Ch] [bp-A8h]@4
  HINTERNET hInternet; // [sp+50h] [bp-A4h]@1
  CHAR szHeaders; // [sp+54h] [bp-A0h]@1
  char v14; // [sp+55h] [bp-9Fh]@1
  char *v15; // [sp+D8h] [bp-1Ch]@1
  HINTERNET hRequest; // [sp+DCh] [bp-18h]@3
  char *reqparam; // [sp+E0h] [bp-14h]@4
  void *v18; // [sp+E4h] [bp-10h]@4
  DWORD dwNumberOfBytesRead; // [sp+E8h] [bp-Ch]@6
  unsigned int v20; // [sp+ECh] [bp-8h]@1
  char *v21; // [sp+F0h] [bp-4h]@1

  v8 = 0;
  v7 = 0;
  getparams = 0;
  memset(&v10, 0, 0x3Fu);
  szHeaders = 0;
  memset(&v14, 0, 0x7Fu);
  v15 = "673278367138713a81462f6f";             // g1v3m3k3y=%d
  v21 = "4370716e6d6a40272d7c1715";             // Cookie: %s
  v20 = *(_DWORD *)a5;
  *(_DWORD *)a5 = 0;
  hInternet = InternetOpenA((LPCSTR)(url_data + 324), 0, 0, 0, 0);// user agent: TMCTF2015-13106
  if ( hInternet )
  {
    hConnect = InternetConnectA(hInternet, lpszServerName, portnum, 0, 0, 3u, 0, 0);
    if ( hConnect )
    {                                           // GET /e45c2dc8d9e5b215ea141f2f609100f9/notify.php
      hRequest = HttpOpenRequestA(hConnect, "GET", (LPCSTR)(url_data + 260), "HTTP/1.0", 0, 0, 0x80000u, 0);
      if ( hRequest )
      {
        reqparam = (char *)decode_string(v15);
        _snprintf(&getparams, 0x3Fu, reqparam, status);
        free(reqparam);
        v18 = get_cookie(&getparams);
        cookieheader = (char *)decode_string(v21);
        _snprintf(&szHeaders, 0x80u, cookieheader, v18);
        free(v18);
        free(cookieheader);
        HttpAddRequestHeadersA(hRequest, &szHeaders, 0xFFFFFFFF, 0xA0000000);
        if ( HttpSendRequestA(hRequest, 0, 0, 0, 0) )
        {
          while ( v7 <= v20 )
          {
            if ( InternetReadFile(hRequest, dstBuffer, v20 - v7, &dwNumberOfBytesRead) )
            {
              if ( !dwNumberOfBytesRead )
              {
                v8 = 1;
                *(_DWORD *)a5 = v7;
                break;
              }
              dstBuffer = (char *)dstBuffer + dwNumberOfBytesRead;
              v7 += dwNumberOfBytesRead;
            }
          }
        }
        InternetCloseHandle(hRequest);
      }
      InternetCloseHandle(hConnect);
    }
    InternetCloseHandle(hInternet);
  }
  return v8;
}
```

We can see that there are 2 actions that can be undertaken after data has been retrieved from the Command & Control server:

```c
int __cdecl write_key_bin(LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite)
{
  signed int v3; // [sp+0h] [bp-Ch]@1
  DWORD NumberOfBytesWritten; // [sp+4h] [bp-8h]@2
  HANDLE hFile; // [sp+8h] [bp-4h]@1

  v3 = 0;
  hFile = CreateFileA((LPCSTR)(url_data + 396), 0x40000000u, 0, 0, 2u, 0x80u, 0);// openfile(key.bin)
  if ( hFile != (HANDLE)-1 )
  {
    WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0);
    CloseHandle(hFile);
    v3 = 1;
  }
  return v3;
}

int do_mutex_stuff()
{
  DWORD nNumberOfBytesToRead; // [sp+4h] [bp-14h]@1
  HANDLE hFile; // [sp+8h] [bp-10h]@1
  void *lpBuffer; // [sp+Ch] [bp-Ch]@3
  HANDLE hObject; // [sp+10h] [bp-8h]@4
  DWORD NumberOfBytesRead; // [sp+14h] [bp-4h]@4

  nNumberOfBytesToRead = get_file_size((LPCSTR)(url_data + 396));// filesize(key.bin)
  hFile = CreateFileA((LPCSTR)(url_data + 396), 0x80000000, 0, 0, 3u, 0, 0);// open(key.bin)
  if ( hFile != (HANDLE)-1 && nNumberOfBytesToRead == 35 )
  {
    lpBuffer = malloc(35u);
    if ( lpBuffer )
    {
      ReadFile(hFile, lpBuffer, 35u, &NumberOfBytesRead, 0);
      extract_mutex(Name, 35, lpBuffer, 35);
      hObject = CreateMutexA(0, 0, Name);
      if ( hObject && GetLastError() == 183 )
      {
        CloseHandle(hObject);
        ExitProcess(0x47414C46u);
      }
      free(lpBuffer);
    }
    CloseHandle(hFile);
  }
  return 0;
}
```

The *write_key_bin* function seems to extract keying data from the response and write it to the *"key.bin"* file. The *do_mutex_stuff* function reads 35 bytes from the key file, applies the *extract_mutex* function to a constant *Name* buffer and obtains a mutex name value which it then proceeds to set. We assume it is the mutex name we are supposed to obtain as a flag value.

Given that we have neither *keyfile.bin* nor will the connection succeed (since it attempts to connect to localhost) we connect to *ctfquest.trendmicro.co.jp|19400* ourselves with user-agent *TMCTF2015-13106* and cookie set to *get_cookie("g1v3m3k3y=1")* and make a GET request to */e45c2dc8d9e5b215ea141f2f609100f9/notify.php* using the following (very dirty) code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>

int main(int argc, unsigned char** argv)
{
    char getParams[0x40] = {0};
    char szHeaders[0x81] = {0};
    char* cookieVal = "673278367138713a81463b"; // g1v3m3k3y=1
    int status = 0;
    DWORD readBytes = 0;
    DWORD bufSZ = 256;
    unsigned char buffer[257] = {0};
    DWORD dwNumberOfBytesRead = 0;
    DWORD a5 = 0;
    unsigned char* dstBuffer = (unsigned char*)buffer;

    HANDLE hInternet = InternetOpenA((LPCSTR)"TMCTF2015-13106", 0, 0, 0, 0);
    if(hInternet)
    {
        HANDLE hConnect = InternetConnectA(hInternet, (LPCSTR)"ctfquest.trendmicro.co.jp", 19400, 0, 0, 3, 0, 0);
        if(hConnect)
        {
            HANDLE hRequest = HttpOpenRequestA(hConnect, "GET", (LPCSTR)"/e45c2dc8d9e5b215ea141f2f609100f9/notify.php", "HTTP/1.0", 0, 0, 0x80000, 0);
            if(hRequest)
            {
                snprintf(getParams, 0x3F, "g1v3m3k3y=%d", status);
                snprintf(szHeaders, 0x80, "Cookie: %s\r\n", cookieVal);

                HttpAddRequestHeadersA(hRequest, &szHeaders, 0xFFFFFFFF, 0xA0000000);

                if(HttpSendRequestA(hRequest, 0, 0, 0, 0))
                {
                    printf("[*] Reading server response...\n");

                    while(readBytes <= bufSZ)
                    {
                        if( InternetReadFile(hRequest, dstBuffer, bufSZ - readBytes, &dwNumberOfBytesRead) )
                        {
                            if( !dwNumberOfBytesRead )
                            {
                                a5 = readBytes;
                                break;
                            }

                            dstBuffer = (unsigned char*)(dstBuffer + dwNumberOfBytesRead);
                            readBytes += dwNumberOfBytesRead;
                        }
                    }

                    printf("[+] Read (%d) bytes\n", a5);

                    printf("[+] Data buffer: [");

                    DWORD kl = a5 - ((unsigned char*)&buffer[2 + buffer[0]] - (unsigned char*)&buffer);
                    DWORD i;

                    printf("[+] Key: [");

                    for(i = 0; i < kl; i++)
                    {
                        printf("%02x", ((unsigned char*)(&buffer[2 + buffer[0]]))[i]);
                    }

                    printf("]\n");
                }
            }
        }
    }

  return 0;
}
```

Which gave us the key buffer:

```
6381b943696db16f13f84ac7176049a9f74025bd779eae5b22a1617423b66e5bf207f6
```

The *extract_mutex* function is a simple repeating-key XOR application of the key to the encrypted mutex name buffer:

```python
def extract_mutex(mutex_buf, mutex_len, key_buf, key_len):
  res = ""
  for i in xrange(mutex_len):
    res += chr(ord(mutex_buf[i]) ^ ord(key_buf[i % key_len]))
  return res

mutex_buf = "\x37\xCC\xFA\x17\x2F\x16\xFC\x39\x2B\x82\x12\xBD\x51\x06\x04\xEF\xCF\x72\x7D\xC7\x25\xF8\xE0\x0D\x1A\x91\x39\x0D\x4B\xD0\x23\x3C\xCF\x3A\x8B"

key_buf = "6381b943696db16f13f84ac7176049a9f74025bd779eae5b22a1617423b66e5bf207f6".decode('hex')

assert(len(mutex_buf) == len(key_buf) == 35)
mutex = extract_mutex(mutex_buf, len(mutex_buf), key_buf, len(key_buf))
print "[+]Mutex: [%s]\n" % mutex
```

Execution of which gives us:

```bash
$ ./getmutex.py
[+]Mutex: [TMCTF{MV8zXzFfMF82XzRfNV80XyhfMg==}]
```