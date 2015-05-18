# DEF CON CTF Quals 2015: accesscontrol

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| DEF CON CTF Quals 2015 | accesscontrol | Reversing |    1 |

**Description:**
>*It's all about [who you know and what you want](challenge/client). access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me:17069*

----------
## Write-up

We're given a client binary and a server address and port. When we connect to the server we're presented with the following:

>```bash
>$ nc access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me 17069
>connection ID: |e?R:/u,`#h%AN
>
>
>*** Welcome to the ACME data retrieval service ***
>
>what version is your client?
>```

We're gonna need to reverse engineer the client binary in order to get (the right kind of) access to the server.

>```bash
>$ file client
> client: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xcf260fd5e12b4ccf789d77ac706a049d83df4f05, stripped
>```

When we execute the client we get the following:

>```bash
>$./client 
>need IP
>$./client 54.84.39.118
>Socket created
>Enter message : 
>```

Let's get some (properly labled) pseudo-code using IDA:

>```c
>signed int __cdecl mainroutine(signed int a1, int a2)
>{
>  signed int result; // eax@2
>  bool v3; // cf@9
>  bool v4; // zf@9
>  signed int v5; // ecx@9
>  int v6; // esi@9
>  int v7; // edi@9
>  void *v8; // edx@26
>  unsigned int v9; // ebx@26
>  int v10; // edi@28
>  int v11; // edx@28
>  void *v12; // edx@34
>  unsigned int v13; // ebx@34
>  int v14; // edi@36
>  int v15; // edx@36
>  void *v16; // edx@43
>  unsigned int v17; // ebx@43
>  int v18; // edi@45
>  int v19; // edx@45
>  int v20; // edx@54
>  signed int message_done; // [sp+24h] [bp-78h]@7
>  __int16 hello_buf; // [sp+2Ah] [bp-72h]@26
>  int v23; // [sp+2Ch] [bp-70h]@27
>  int ip_addr; // [sp+5Ch] [bp-40h]@3
>  signed __int16 v25; // [sp+70h] [bp-2Ch]@5
>  uint16_t v26; // [sp+72h] [bp-2Ah]@5
>  in_addr_t v27; // [sp+74h] [bp-28h]@5
>  int password; // [sp+80h] [bp-1Ch]@25
>  __int16 v29; // [sp+84h] [bp-18h]@25
>  int response; // [sp+86h] [bp-16h]@51
>  __int16 v31; // [sp+8Ah] [bp-12h]@51
>  int v32; // [sp+8Ch] [bp-10h]@1
>
>  v32 = *MK_FP(__GS__, 20);
>  if ( a1 > 1 )
>  {
>    strncpy((char *)&ip_addr, *(const char **)(a2 + 4), 0x14u);
>    fd = socket(2, 1, 0);
>    if ( fd == -1 )
>      printf("Could not create socket");
>    puts("Socket created");
>    v27 = inet_addr((const char *)&ip_addr);
>    v25 = 2;
>    v26 = htons(0x42ADu);
>    if ( connect(fd, (const struct sockaddr *)&v25, 0x10u) >= 0 )
>    {
>      client_state = 0;
>      message_done = 0;
>      *(_DWORD *)challenge = 0;
>      word_804B470 = 0;
>      *(_DWORD *)connection_id = 0;
>      dword_804BC74 = 0;
>      dword_804BC78 = 0;
>      word_804BC7C = 0;
>      byte_804BC7E = 0;
>      while ( 1 )
>      {
>        memset(message, 0, sizeof(message));
>        if ( !message_done )
>        {
>          printf("Enter message : ");
>          fgets(message, 1000, stdin);
>          v5 = 16;
>          v6 = (int)message;
>          v7 = (int)"hack the world\n";
>          do
>          {
>            if ( !v5 )
>              break;
>            v3 = *(_BYTE *)v6 < *(_BYTE *)v7;
>            v4 = *(_BYTE *)v6++ == *(_BYTE *)v7++;
>            --v5;
>          }
>          while ( v4 );
>          if ( (!v3 && !v4) != v3 )
>          {
>            printf("nope...%s\n", message);
>            result = -1;
>            goto exit_label;
>          }
>          memset(message, 0, sizeof(message));
>          message_done = 1;
>        }
>        if ( client_state == 1 )
>        {
>          send_line("grumpy\n");
>          username = *(_DWORD *)"grumpy";
>          word_804B476 = *(_WORD *)"py";
>          byte_804B478 = aGrumpy_0[6];
>          recv_until("enter user password");
>          if ( recv_until("enter user password") )
>          {
>            password = 0;
>            v29 = 0;
>            get_password((int)"grumpy", (int)&password);
>            decode_password((int)&password);
>            HIBYTE(v29) = 0;
>            sprintf((char *)&password, "%s\n", &password);
>            send_line(&password);
>          }
>          v8 = &hello_buf;
>          v9 = 50;
>          if ( (unsigned int)&hello_buf & 2 )
>          {
>            hello_buf = 0;
>            v8 = &v23;
>            v9 = 48;
>          }
>          memset(v8, 0, 4 * (v9 >> 2));
>          v10 = (int)((char *)v8 + 4 * (v9 >> 2));
>          v11 = (int)((char *)v8 + 4 * (v9 >> 2));
>          if ( v9 & 2 )
>          {
>            *(_WORD *)v10 = 0;
>            v11 = v10 + 2;
>          }
>          if ( v9 & 1 )
>            *(_BYTE *)v11 = 0;
>          sprintf((char *)&hello_buf, "hello %s, what would you like to do?", &username);
>          if ( recv_until((char *)&hello_buf) )
>            client_state = 2;
>        }
>        else if ( (unsigned int)client_state < 1 )
>        {
>          if ( recv_until("what version is your client?") )
>          {
>            dword_804BC80 = SBYTE3(dword_804BC74);
>            send_line("version 3.11.54\n");
>          }
>          if ( recv_until("hello...who is this?") )
>            client_state = 1;
>        }
>        else if ( client_state == 2 )
>        {
>          send_line("list users\n");
>          recv_until("deadwood");
>          v12 = &hello_buf;
>          v13 = 50;
>          if ( (unsigned int)&hello_buf & 2 )
>          {
>            hello_buf = 0;
>            v12 = &v23;
>            v13 = 48;
>          }
>          memset(v12, 0, 4 * (v13 >> 2));
>          v14 = (int)((char *)v12 + 4 * (v13 >> 2));
>          v15 = (int)((char *)v12 + 4 * (v13 >> 2));
>          if ( v13 & 2 )
>          {
>            *(_WORD *)v14 = 0;
>            v15 = v14 + 2;
>          }
>          if ( v13 & 1 )
>            *(_BYTE *)v15 = 0;
>          sprintf((char *)&hello_buf, "hello %s, what would you like to do?", &username);
>          if ( recv_until((char *)&hello_buf) )
>          {
>            send_line("print key\n");
>            recv_until("the key is:");
>          }
>          client_state = 0;
>        }
>        else if ( client_state == 3 )
>        {
>          send_line("list users\n");
>          recv_until("deadwood");
>          v16 = &hello_buf;
>          v17 = 50;
>          if ( (unsigned int)&hello_buf & 2 )
>          {
>            hello_buf = 0;
>            v16 = &v23;
>            v17 = 48;
>          }
>          memset(v16, 0, 4 * (v17 >> 2));
>          v18 = (int)((char *)v16 + 4 * (v17 >> 2));
>          v19 = (int)((char *)v16 + 4 * (v17 >> 2));
>          if ( v17 & 2 )
>          {
>            *(_WORD *)v18 = 0;
>            v19 = v18 + 2;
>          }
>          if ( v17 & 1 )
>            *(_BYTE *)v19 = 0;
>          sprintf((char *)&hello_buf, "hello %s, what would you like to do?", &username);
>          if ( recv_until((char *)&hello_buf) )
>          {
>            send_line("print key\n");
>            recv_until("challenge:");
>            if ( recv_until("answer?") )
>            {
>              password = 0;
>              v29 = 0;
>              conn_id_index = 7;
>              HIBYTE(word_804B470) = 0;
>              get_password((int)challenge, (int)&password);
>              conn_id_index = 1;
>              decode_password((int)&password);
>              HIBYTE(v29) = 0;
>              response = 0;
>              v31 = 0;
>              strncpy((char *)&response, (const char *)&password, 5u);
>              HIBYTE(v31) = 10;
>              send_line(&response);
>              recv_until("the key is:");
>              recv_until((char *)&hello_buf);
>            }
>          }
>          client_state = 0;
>        }
>        else
>        {
>          client_state = 0;
>        }
>      }
>    }
>    perror("connect failed. Error");
>    result = 1;
>  }
>  else
>  {
>    puts("need IP");
>    result = -1;
>  }
>exit_label:
>  v20 = *MK_FP(__GS__, 20) ^ v32;
>  return result;
>}
>```

We can see that there are 4 different client states where the client derives a password from the randomized connection ID, logs in and performs some actions. The client initially expects us to enter the message "hack the world" before it enters client states 0 through 2, which gives the following output:

>```bash
>$./client 54.84.39.118
>Socket created
>Enter message : hack the world
><< connection ID: i^:WkYL5@eYT(x
>
>
>*** Welcome to the ACME data retrieval service ***
>what version is your client?
>
><< hello...who is this?
><< 
>
><< enter user password
>
><< hello grumpy, what would you like to do?
>
><< grumpy
><< 
>mrvito
>gynophage
>selir
>jymbolia
>sirgoon
>duchess
>deadwood
>hello grumpy, what would you like to do?
>
><< the key is not accessible from this account. your administrator has been notified.
><< 
>hello grumpy, what would you like to do?
>```

So what do we currently have?

* Server address and port
* list of usernames: grumpy, mrvito, gynophage, selir, jymbolia, sirgoon, duchess, deadwood
* list of commands: list users, print key
* password derivation algorithm

So the proper course of action seems to be to reverse engineer the password derivation algorithm, find a user which is allowed to print the key (who will most likely be presented with a challenge as per the otherwise unreachable client state 3), respond to the challenge and grab the key.

The password derivation algorithm consists of 2 functions (get_password and decode_password):

>```c
>char *__cdecl get_password(int a1, int a2)
>{
>  char *result; // eax@1
>  int v3; // ebx@4
>  signed int i; // [sp+2Ch] [bp-1Ch]@1
>  char dest[5]; // [sp+37h] [bp-11h]@1
>  int v6; // [sp+3Ch] [bp-Ch]@1
>
>  v6 = *MK_FP(__GS__, 20);
>  result = strncpy(dest, &connection_id[conn_id_index] + some_offset % 3, 5u);
>  for ( i = 0; i <= 4; ++i )
>  {
>    result = (char *)(a2 + i);
>    *(_BYTE *)(a2 + i) = dest[i] ^ *(_BYTE *)(a1 + i);
>  }
>  v3 = *MK_FP(__GS__, 20) ^ v6;
>  return result;
>}
>```

The above function simply indexes the received connection id based on conn_id_index and some_offset (which is initialized by dword_804BC80 = SBYTE3(dword_804BC74)) and takes 5 bytes which it xors with the first parameter (which is the username). The result is then supplied to the following function:

>```c
>int __cdecl decode_password(int a1)
>{
>  int result; // eax@4
>  signed int i; // [sp+Ch] [bp-4h]@1
>
>  for ( i = 0; i <= 4; ++i )
>  {
>    if ( *(_BYTE *)(a1 + i) <= 31 )
>      *(_BYTE *)(a1 + i) += 32;
>    result = *(_BYTE *)(a1 + i);
>    if ( (_BYTE)result == 127 )
>    {
>      *(_BYTE *)(a1 + i) -= 126;
>      result = a1 + i;
>      *(_BYTE *)(a1 + i) += 32;
>    }
>  }
>  return result;
>}
>```

which simply translates it to a printable form.

Next we simply iterate over all the usernames until we find one which is presented with a challenge (which turns out to be the user duchess) and generate a response to the challenge using the password derivation algorithm before issuing the print key command. Tying this all together gives us the [following script](solution/accesscontrol_crack.py):

>```python
>#!/usr/bin/python
>#
># DEF CON CTF Quals 2015
># dark (REVERSING/1)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
>from pwn import *
>from struct import unpack
>
>def get_password(a1, connection_id, conn_id_index, dword_804BC80):
>	a2 = ""
>
>	offset = conn_id_index + (dword_804BC80 % 3)
>	dest = connection_id[offset: offset+5]
>
>	for i in xrange(5):
>		a2 += chr(ord(dest[i]) ^ ord(a1[i]))
>	return a2
>
>def decode_password(a1):
>	result = list()
>	a2 = list(a1)
>	for i in xrange(5):
>		if(ord(a2[i]) <= 31):
>			a2[i] = chr(ord(a2[i]) + 32)
>		result = a2[i]
>		if(ord(result) == 127):
>			a2[i] = chr(ord(a2[i]) - 126)
>			result = a2[i: ]
>			a2[i] = chr(ord(a2[i]) + 32)
>	return result, "".join(a2)
>
>def handshake(h):
>	version = "version 3.11.54"
>	msg = h.recvuntil("what version is your client?\n")
>	c_offset = msg.find("connection ID: ")
>	connection_id = msg[c_offset+15: c_offset+29]
>	h.send(version + "\n")
>	msg = h.recvuntil("hello...who is this?\n")
>	return connection_id
>
>def login(h, username, connection_id, conn_id_index, dword_804BC80, hello_str):
>	h.send(username + "\n")
>	msg = h.recvuntil("enter user password\n")
>
>	pwd = get_password(username, connection_id, conn_id_index, dword_804BC80)
>	res, pwd = decode_password(pwd)
>
>	print "Password: [%s]" % pwd
>
>	password = "%s" % pwd
>	h.send(password + "\n")
>	msg = h.recvuntil(hello_str)
>	return True
>
>def list_users(h):
>	h.send("list users\n")
>	msg = h.recvuntil("deadwood\n")
>
>	print "Users: [%s]" % msg
>	return
>
>def print_key_challenge(h, connection_id, dword_804BC80):
>	h.send("print key\n")
>	msg = h.recv(2048)
>
>	c_offset = msg.find("challenge: ")
>	challenge = msg[c_offset+11: c_offset+16]
>
>	print "Challenge: [%s]" % challenge
>
>	msg = h.recvuntil("answer?\n")
>	conn_id_index = 7
>	pwd = get_password(challenge, connection_id, conn_id_index, dword_804BC80)
>	conn_id_index = 1
>	res, pwd = decode_password(pwd)
>
>	response = pwd[0: 5]
>	h.send(response + "\n")
>
>	msg = h.recv(2048)
>	
>	offset = msg.find("the key is: ")
>	key = msg[offset+12: ]
>	print "Key: [%s]" % key
>	return
>
>username = "duchess"
>client_state = 0
>conn_id_index = 1
>dword_804BC80 = 0
>hello_str = "hello %s, what would you like to do?\n" % username
>
>host = 'access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me'
>port = 17069
>
>h = remote(host, port, timeout = None)
>
>while(True):
>	if(client_state == 0):
>		connection_id = handshake(h)
>		print "Connection ID: [%s]" % connection_id
>		second_dword = connection_id[4: 8]
>		dword_804BC80 = unpack('B', second_dword[3])[0]
>		client_state = 1
>	elif(client_state == 1):
>		if(login(h, username, connection_id, conn_id_index, dword_804BC80, hello_str)):
>			client_state = 2
>		else:
>			raise Exception("[-]Incorrect login for '%s'" % username)
>	elif(client_state == 2):
>		print_key_challenge(h, connection_id, dword_804BC80)
>		break
>
>h.close()
>```

Which gives the following output:

>```c
>$./accesscontrol_crack.py 
>[+] Opening connection to access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me on port 17069: Done
>Connection ID: [%KU[G.[Rl/97Mm]
>Password: [1.$F>]
>Challenge: [J.1$J]
>Key: [The only easy day was yesterday. 44564
>
>]
>```