# ASIS CTF Quals 2015: leach

----------
## Challenge details
| Contest        | Challenge     | Category  | Points |
|:---------------|:--------------|:----------|-------:|
| ASIS CTF Quals 2015 | leach | Reversing |    250 |

**Description:**
>*Find the flag in this [file](challenge/leach).*

----------
## Write-up

Let's take a look at the file:

>```bash
>file leach
>leach; ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, stripped
>```

If we run it, it starts waiting for a long time and playing pong:

>```bash
>$ ./leach
>
>this may take too long time ... :)
>
>##############################
>#|                           #
># 						   #
>#                            #
>#                           |#
>#             o              #
>#                            #
>#                            #
>#                            #
>##############################
>```

and fire it up in IDA to get some pseudocode. The relevant part of the main routine is the following:

>```c
>__int64 __fastcall mainroutine(__int64 a1, __int64 a2)
>{
>
>	 (...)
>
>    while ( 1 )
>    {
>      src = off_602540[v13];
>      if ( !src )
>        break;
>      v12 = time(0LL);
>      sleep(*(&seconds + v13));
>      v11 = (unsigned __int64)time(0LL) - v12;
>      sprintf(&s, "%d", v11, v4);
>      strcpy(&dest, src);
>      strcat(&dest, &s);
>      if ( !sub_400D65(&dest, (unsigned int)dword_602300[v13], &v8) )
>      {
>        LODWORD(v3) = sub_400DDD(&dest);
>        printf(v3);
>        dword_602BF8 = 0;
>      }
>      ++v13;
>    }
>    putchar(10);
>    result = 0LL;
>  }
>  return result;
>}
>```

As we can see v11 is the difference between two timestamps taken with a sleep operation in between (which will sleep for a number of seconds determined by index v13 in table seconds). v11 is then combined with variables retrieved from tables off_602540 and dword_602300 and put into function sub_400D65 which will decide whether to call the (presumable) decryption function sub_400DDD or not, using the constructed argument, and output the result. So without looking any further at these subroutines, let's first eliminate the delay by simply setting v11 to seconds[v13] immediately without sleep in between. The disassembly of the relevant code looks as follows:

>```asm
>.text:0000000000401121                 mov     edi, 0          ; timer
>.text:0000000000401126                 call    _time
>.text:000000000040112B                 mov     [rbp+var_8], eax
>.text:000000000040112E                 mov     eax, [rbp+var_4]
>.text:0000000000401131                 cdqe
>.text:0000000000401133                 mov     eax, seconds[rax*4]
>.text:000000000040113A                 mov     edi, eax        ; seconds
>.text:000000000040113C                 call    _sleep
>.text:0000000000401141                 mov     edi, 0          ; timer
>.text:0000000000401146                 call    _time
>.text:000000000040114B                 mov     edx, eax
>.text:000000000040114D                 mov     eax, [rbp+var_8]
>.text:0000000000401150                 sub     edx, eax
>.text:0000000000401152                 mov     eax, edx
>.text:0000000000401154                 mov     [rbp+var_C], eax
>```

So all we need to do is patch out the instructions from 0x040113A to 0x0401152 to make sure the right value goes from the lookup table to v11 (indicated by [rbp+var_C]). We do this in IDA by using edit -> patch program -> change byte and change the entire range to NOP (0x90) instructions. We then generate an IDA diff file by using File -> Produce file -> Create DIF file which produces the [following file](solution/leach.dif):

>```
>This difference file has been created by IDA
>
>leach.bak
>000000000000113A: 89 90
>000000000000113B: C7 90
>000000000000113C: E8 90
>000000000000113D: 3F 90
>000000000000113E: F8 90
>000000000000113F: FF 90
>0000000000001140: FF 90
>0000000000001141: BF 90
>0000000000001142: 00 90
>0000000000001143: 00 90
>0000000000001144: 00 90
>0000000000001145: 00 90
>0000000000001146: E8 90
>0000000000001147: F5 90
>0000000000001148: F7 90
>0000000000001149: FF 90
>000000000000114A: FF 90
>000000000000114B: 89 90
>000000000000114C: C2 90
>000000000000114D: 8B 90
>000000000000114E: 45 90
>000000000000114F: F8 90
>0000000000001150: 29 90
>0000000000001151: C2 90
>0000000000001152: 89 90
>0000000000001153: D0 90
>
>```

And then supply the resulting DIF to the [following IDA dif patcher](http://stalkr.net/files/ida/idadif.py) to produce a patched binary:

>```bash
>$ ./idadif.py ./leach ./leach.dif
>Patching file './leach' with './leach.dif'
>Done
>```

Which when run gives us the flag:

>```bash
>$ ./leach
>this may take too long time ... :)
>ASIS
>##############################
>{f18b0b4f1bc6c8af21a4a53ef002f9a2}
>```