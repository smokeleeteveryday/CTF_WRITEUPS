# BCTF 2016: sif

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| BCTF | sif | Misc. | 350 |

### Description
> [sif.fd5d0eb0e7a0fdc2b0a8fad3e0015552](challenge)
>
> [flag.png.bf845d7e9972c0c05906f8d0eb831ff4](challenge)

## Write-up

This challenge consisted of two files, a file named [sif](challenge/sif) and an apparently encrypted PNG file named [flag.png](challenge/flag.png). When trying to identify `sif` the usual file command was of no use:

```bash
file sif
sif; data
```

Taking a look with a hex editor revealed the first 6 bytes to be `"\xFA\xFARIQS"` which turned out to be the header magic for [compiled squirrel files](https://en.wikipedia.org/wiki/Squirrel_(programming_language)).

```
Offset      0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F

00000000   FA FA 52 49 51 53 01 00  00 00 08 00 00 00 04 00   úúRIQS          
00000010   00 00 54 52 41 50 10 00  00 08 07 00 00 00 00 00     TRAP          
00000020   00 00 73 69 66 2E 6E 75  74 10 00 00 08 04 00 00     sif.nut       
00000030   00 00 00 00 00 6D 61 69  6E 54 52 41 50                 mainTRAP
```

Squirrel is a high level imperative OO scripting language for lightweight purposes apparently used in game development. The language (and especially its compiled `cnut` format) turned out to not be all that well documented but we stumbled upon an [existing decompiler](https://github.com/darknesswind/NutCracker). The decompiler, however, failed to properly decompile `sif` with the following error:

```bash
nutcracker.exe sif
Error: Bad format of source binary file (PART marker was not match).
```

So we took about reversing the `cnut` format a bit and fixing the decompiler where necessary. It turns out the `cnut` header looks roughly as follows:

> [header magic (6 bytes)] [size of char (4 bytes)] [size of int (4 bytes)] [size of float (4 bytes)] [PART (in little endian)]

So the 3rd to 5th data field of the header indicate the sizes it uses for elementary datatypes and we can also see every info section in `cnut` files is terminated by an expected `PART` marker to indicate we're properly parsing. When we look at the source-code of the decompiler we see the following:

```cpp
void NutFunction::Load( BinaryReader& reader )
{
    reader.ConfirmOnPart();

    reader.ReadSQStringObject(m_SourceName);
    reader.ReadSQStringObject(m_Name);

    reader.ConfirmOnPart();
    
    int nLiterals = reader.ReadInt32();
    int nParameters = reader.ReadInt32();
    int nOuterValues = reader.ReadInt32();
    int nLocalVarInfos = reader.ReadInt32();
    int nLineInfos = reader.ReadInt32();
    int nDefaultParams = reader.ReadInt32();
    int nInstructions = reader.ReadInt32();
    int nFunctions = reader.ReadInt32();
```

The problem here is that the ubiquitous use of `ReadInt32()` doesn't work since in our `sif` file our integer size is 8 bytes rather than 4. As such we modified the decompiler source by adding `ReadInt64()` to its definitions and modifying the decompiler to use that instead of `ReadInt32()` where necessary:

```cpp
int64_t         ReadInt64( void ){ return ReadValue<int64_t>(); }
```

After working our way through the decompiler source to address this problem we ran the fixed decompiler against `sif` and it spew out the following squirrel decompilation:

```c
  // [001]  OP_NEWOBJ         3        -1   -1    2
$[stack offset 3].A <- 0;
$[stack offset 3].B <- 0;
$[stack offset 3].C <- 0;
$[stack offset 3].D <- 0;
$[stack offset 3].buf <- null;
$[stack offset 3].size <- 0;
$[stack offset 3].constructor <- function ()
{
    this.A = 1732584193;
    this.B = 4023233417;
    this.C = 2562383102;
    this.D = 271733878;
    this.buf = this.blob();
    this.size = 0;
};
$[stack offset 3]._update_block <- function ( data )
{
      // [000]  OP_NEWOBJ         2         0    0    1
    local i = 0;
      // [003]  OP_JCMP           4         9    3    3
    i++;
      // [012]  OP_JMP            0       -11    0    0
    local F = function ( x, y, z )
    {
        return x & y | ~x & z;
    };
    local G = function ( x, y, z )
    {
        return x & z | y & ~z;
    };
    local H = function ( x, y, z )
    {
        return x ^ y ^ z;
    };
    local I = function ( x, y, z )
    {
        return (y ^ (x | ~z)) & 4294967295;
    };
    local Z = function ( f, a, b, c, d, x, s, t )
    {
        a = a + f(b, c, d) + x + t & 4294967295;
        a = a << s & 4294967295 | (a & 4294967295) << 32 - s;
        return a + b;
    };
      // [018]  OP_NEWOBJ         8        68    0    1
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    $[stack offset 8].append($[stack offset 8], $[stack offset 2].append(data.readn(105) & 4294967295));
    local a = this.A;
    local b = this.B;
    local c = this.C;
    local d = this.D;
    a = Z(F, a, b, c, d, $[stack offset 2][0], 7, $[stack offset 8][0]);
    d = Z(F, d, a, b, c, $[stack offset 2][1], 12, $[stack offset 8][1]);
    c = Z(F, c, d, a, b, $[stack offset 2][2], 17, $[stack offset 8][2]);
    b = Z(F, b, c, d, a, $[stack offset 2][3], 22, $[stack offset 8][3]);
    a = Z(F, a, b, c, d, $[stack offset 2][4], 7, $[stack offset 8][4]);
    d = Z(F, d, a, b, c, $[stack offset 2][5], 12, $[stack offset 8][5]);
    c = Z(F, c, d, a, b, $[stack offset 2][6], 17, $[stack offset 8][6]);
    b = Z(F, b, c, d, a, $[stack offset 2][7], 22, $[stack offset 8][7]);
    a = Z(F, a, b, c, d, $[stack offset 2][8], 7, $[stack offset 8][8]);
    d = Z(F, d, a, b, c, $[stack offset 2][9], 12, $[stack offset 8][9]);
    c = Z(F, c, d, a, b, $[stack offset 2][10], 17, $[stack offset 8][10]);
    b = Z(F, b, c, d, a, $[stack offset 2][11], 22, $[stack offset 8][11]);
    a = Z(F, a, b, c, d, $[stack offset 2][12], 7, $[stack offset 8][12]);
    d = Z(F, d, a, b, c, $[stack offset 2][13], 12, $[stack offset 8][13]);
    c = Z(F, c, d, a, b, $[stack offset 2][14], 17, $[stack offset 8][14]);
    b = Z(F, b, c, d, a, $[stack offset 2][15], 22, $[stack offset 8][15]);
    a = Z(G, a, b, c, d, $[stack offset 2][1], 5, $[stack offset 8][16]);
    d = Z(G, d, a, b, c, $[stack offset 2][6], 9, $[stack offset 8][17]);
    c = Z(G, c, d, a, b, $[stack offset 2][11], 14, $[stack offset 8][18]);
    b = Z(G, b, c, d, a, $[stack offset 2][0], 20, $[stack offset 8][19]);
    a = Z(G, a, b, c, d, $[stack offset 2][5], 5, $[stack offset 8][20]);
    d = Z(G, d, a, b, c, $[stack offset 2][10], 9, $[stack offset 8][21]);
    c = Z(G, c, d, a, b, $[stack offset 2][15], 14, $[stack offset 8][22]);
    b = Z(G, b, c, d, a, $[stack offset 2][4], 20, $[stack offset 8][23]);
    a = Z(G, a, b, c, d, $[stack offset 2][9], 5, $[stack offset 8][24]);
    d = Z(G, d, a, b, c, $[stack offset 2][14], 9, $[stack offset 8][25]);
    c = Z(G, c, d, a, b, $[stack offset 2][3], 14, $[stack offset 8][26]);
    b = Z(G, b, c, d, a, $[stack offset 2][8], 20, $[stack offset 8][27]);
    a = Z(G, a, b, c, d, $[stack offset 2][13], 5, $[stack offset 8][28]);
    d = Z(G, d, a, b, c, $[stack offset 2][2], 9, $[stack offset 8][29]);
    c = Z(G, c, d, a, b, $[stack offset 2][7], 14, $[stack offset 8][30]);
    b = Z(G, b, c, d, a, $[stack offset 2][12], 20, $[stack offset 8][31]);
    a = Z(H, a, b, c, d, $[stack offset 2][5], 4, $[stack offset 8][32]);
    d = Z(H, d, a, b, c, $[stack offset 2][8], 11, $[stack offset 8][33]);
    c = Z(H, c, d, a, b, $[stack offset 2][11], 16, $[stack offset 8][34]);
    b = Z(H, b, c, d, a, $[stack offset 2][14], 23, $[stack offset 8][35]);
    a = Z(H, a, b, c, d, $[stack offset 2][1], 4, $[stack offset 8][36]);
    d = Z(H, d, a, b, c, $[stack offset 2][4], 11, $[stack offset 8][37]);
    c = Z(H, c, d, a, b, $[stack offset 2][7], 16, $[stack offset 8][38]);
    b = Z(H, b, c, d, a, $[stack offset 2][10], 23, $[stack offset 8][39]);
    a = Z(H, a, b, c, d, $[stack offset 2][13], 4, $[stack offset 8][40]);
    d = Z(H, d, a, b, c, $[stack offset 2][0], 11, $[stack offset 8][41]);
    c = Z(H, c, d, a, b, $[stack offset 2][3], 16, $[stack offset 8][42]);
    b = Z(H, b, c, d, a, $[stack offset 2][6], 23, $[stack offset 8][43]);
    a = Z(H, a, b, c, d, $[stack offset 2][9], 4, $[stack offset 8][44]);
    d = Z(H, d, a, b, c, $[stack offset 2][12], 11, $[stack offset 8][45]);
    c = Z(H, c, d, a, b, $[stack offset 2][15], 16, $[stack offset 8][46]);
    b = Z(H, b, c, d, a, $[stack offset 2][2], 23, $[stack offset 8][47]);
    a = Z(I, a, b, c, d, $[stack offset 2][0], 6, $[stack offset 8][48]);
    d = Z(I, d, a, b, c, $[stack offset 2][7], 10, $[stack offset 8][49]);
    c = Z(I, c, d, a, b, $[stack offset 2][14], 15, $[stack offset 8][50]);
    b = Z(I, b, c, d, a, $[stack offset 2][5], 21, $[stack offset 8][51]);
    a = Z(I, a, b, c, d, $[stack offset 2][12], 6, $[stack offset 8][52]);
    d = Z(I, d, a, b, c, $[stack offset 2][3], 10, $[stack offset 8][53]);
    c = Z(I, c, d, a, b, $[stack offset 2][10], 15, $[stack offset 8][54]);
    b = Z(I, b, c, d, a, $[stack offset 2][1], 21, $[stack offset 8][55]);
    a = Z(I, a, b, c, d, $[stack offset 2][8], 6, $[stack offset 8][56]);
    d = Z(I, d, a, b, c, $[stack offset 2][15], 10, $[stack offset 8][57]);
    c = Z(I, c, d, a, b, $[stack offset 2][6], 15, $[stack offset 8][58]);
    b = Z(I, b, c, d, a, $[stack offset 2][13], 21, $[stack offset 8][59]);
    a = Z(I, a, b, c, d, $[stack offset 2][4], 6, $[stack offset 8][60]);
    d = Z(I, d, a, b, c, $[stack offset 2][11], 10, $[stack offset 8][61]);
    c = Z(I, c, d, a, b, $[stack offset 2][2], 15, $[stack offset 8][62]);
    b = Z(I, b, c, d, a, $[stack offset 2][9], 21, $[stack offset 8][63]);
    this.A = this.A + a & 4294967295;
    this.B = this.B + b & 4294967295;
    this.C = this.C + c & 4294967295;
    this.D = this.D + d & 4294967295;
};
$[stack offset 3].update <- function ( data )
{
    while (!data.eos())
    {
        this.buf.seek(0, 101);
        this.buf.writeblob(data.readblob(64 - this.buf.len()));

        if (this.buf.len() == 64)
        {
            this.buf.seek(0);
            this._update_block(this.buf);
            this.buf.resize(0);
        }
    }

    this.size += data.len();
};
$[stack offset 3].final <- function ()
{
    this.buf.seek(0, 101);
    this.buf.writen(128, 98);
    64 - this.buf.len();
      // [016]  OP_JCMP           2        22    1    3
    this.buf.len();
      // [021]  OP_JCMP           2         6    1    3
    this.buf.writen(0, 98);
      // [027]  OP_JMP            0       -11    0    0
    this.buf.seek(0);
    this._update_block(this.buf);
    this.buf.resize(0);
    this.buf.len();
    64 - 8;
      // [045]  OP_JCMP           2         6    1    3
    this.buf.writen(0, 98);
      // [051]  OP_JMP            0       -13    0    0
    this.buf.writen(this.size * 8, 108);
    this.buf.seek(0);
    this._update_block(this.buf);
    this.buf.resize(0);
    local result = this.blob();
    result.writen(this.A, 105);
    result.writen(this.B, 105);
    result.writen(this.C, 105);
    result.writen(this.D, 105);
    result.seek(0);
    return result;
};
this.MaryTheFifthDumplingsCook <- $[stack offset 3];
local str2blob = function ( str )
{
    local result = this.blob();

    foreach( x in str )
    {
        result.writen(x, 98);
    }

    result.seek(0);
    return result;
};
  // [035]  OP_NEWOBJ         4        -1   -1    2
$[stack offset 4].salt <- "";
$[stack offset 4].fn <- "";
$[stack offset 4].fileobj <- null;
$[stack offset 4].mana <- null;
  // [047]  OP_NEWOBJ         6         2    0    1
$[stack offset 6].append($[stack offset 6], $[stack offset 8]);
$[stack offset 6].append($[stack offset 6], $[stack offset 8]);
$[stack offset 4].cur <- $[stack offset 6];
$[stack offset 4].pos <- 0;
$[stack offset 4].header <- null;
$[stack offset 4].buffer <- this.blob(0);
$[stack offset 4].constructor <- function ( salt, fn, fileobj )
{
    this.salt = salt;
    this.fileobj = fileobj;
    local i = fn.len() - 1;

    while (i && fn[i] != 47 && fn[i] != 92)
    {
        i--;
    }

    this.fn = fn.slice(i);
    this.seek(0);
};
$[stack offset 4].seek <- function ( offset, origin = 98 ) : ( str2blob )
{
    if (origin != 98 || offset != 0)
    {
        throw "not implemented";
    }

    local engine = this.MaryTheFifthDumplingsCook();
      // [012]  OP_GETOUTER       6         0    0    0
    engine.update($[stack offset 6](this.salt + this.fn));
    local digest = engine.final();
    this.header = digest.readblob(8);
    this.mana = this.magic(digest.readn(108) & 4294967295);
    this.pos = 0;
    this.fileobj.seek(offset);
};
$[stack offset 4].eos <- function ()
{
    return this.header.eos() && this.fileobj.eos();
};
$[stack offset 4].magic <- function ( x )
{
    // Function is a generator.
    while (true)
    {
        yield x;
        x = x * 3740067437 + 11;
        x = x & (1 << 48) - 1;
    }
};
$[stack offset 4].readblob <- function ( size )
{
    local result = this.blob(0);

    if (size && !this.header.eos())
    {
        local t = this.header.readblob(size);
        size = size - t.len();
        result.writeblob(t);
    }

    if (size && !this.fileobj.eos())
    {
        local i = 0;
          // [030]  OP_JCMP           1        46    3    3

        if (this.fileobj.eos())
        {
        }
        else
        {
            if (this.pos == 0)
            {
                local rk = resume this.mana;
                  // [043]  OP_NEWOBJ         6         4    0    1
                $[stack offset 6].append($[stack offset 6], rk << 40);
                $[stack offset 6].append($[stack offset 6], rk << 32);
                $[stack offset 6].append($[stack offset 6], rk << 24);
                $[stack offset 6].append($[stack offset 6], rk << 16Press any key to continue . . . 
);
                this.cur = $[stack offset 6];
            }

            result.writen(this.fileobj.readn(98) ^ this.cur[this.pos], 98);
            this.pos = this.pos + 1 & 3;
            i++;
              // [076]  OP_JMP            0       -47    0    0
        }
    }

    return result;
};
this.ClabEncryptionStream <- $[stack offset 4];
local print_banner = function ()
{
    this.print(" \r\n ,;;:;,                       \r\n   ;;;;;                \r\n  ,:;;:;    ,\'=.          Squirrel Idol Festival\r\n  ;:;:;\' .=\" ,\'_\\     - an encrypt-only file vault\r\n  \':;:;,/  ,__:=@        \r\n   \';;:;  =./)_        We love nuts and your filez!\r\n     `\"=\\_  )_\"`        \r\n          ``\'\"`\r\n");
};
local main = function ( args ) : ( print_banner )
{
      // [000]  OP_GETOUTER       2         0    0    0
    $[stack offset 2]();
    local key = "BCTF{Apparently this is a fake flag}";

    if (args.len() == 2)
    {
        key = args[1];
    }
    else if (args.len() != 1)
    {
        this.print("Usage: sif <file> [key]\n");
        return;
    }

    this.srand(this.time());
    local enc = this.ClabEncryptionStream(key, args[0], this.file(args[0], "rb"));
    local tmpfile = "tmp-" + this.rand().tostring();
    local out = this.file(tmpfile, "wb");

    while (!enc.eos())
    {
        out.writeblob(enc.readblob(4096));
    }

    out.close();
    this.remove(args[0]);
    this.rename(tmpfile, args[0]);
    this.print("Done! Now cracking your file is as hard as cracking nuts :)\n");
};
main(vargv);
```

Taking a look at the `main` function we see the following is done:

```c
    local enc = this.ClabEncryptionStream(key, args[0], this.file(args[0], "rb"));
    local tmpfile = "tmp-" + this.rand().tostring();
    local out = this.file(tmpfile, "wb");

    while (!enc.eos())
    {
        out.writeblob(enc.readblob(4096));
    }

    out.close();
```

So a user-supplied key is taken and fed together with the target file to an encryption object which writes the ciphertext to a new file. Taking a look at `ClabEncryptionStream` (which resides at `this.ClabEncryptionStream <- $[stack offset 4];`) shows its constructor to do the following:

```c
$[stack offset 4].constructor <- function ( salt, fn, fileobj )
{
    this.salt = salt;
    this.fileobj = fileobj;
    local i = fn.len() - 1;

    while (i && fn[i] != 47 && fn[i] != 92)
    {
        i--;
    }

    this.fn = fn.slice(i);
    this.seek(0);
};
```

So we assign our key to `this.salt` and take discard the path from the target filename and assign the result to `this.fn` after which we call `seek` which looks as follows:

```c
$[stack offset 4].seek <- function ( offset, origin = 98 ) : ( str2blob )
{
    if (origin != 98 || offset != 0)
    {
        throw "not implemented";
    }

    local engine = this.MaryTheFifthDumplingsCook();
      // [012]  OP_GETOUTER       6         0    0    0
    engine.update($[stack offset 6](this.salt + this.fn));
    local digest = engine.final();
    this.header = digest.readblob(8);
    this.mana = this.magic(digest.readn(108) & 4294967295);
    this.pos = 0;
    this.fileobj.seek(offset);
};
```

Here `engine` is constructed using the `MaryTheFifthDumplingsCook` object and we feed the concatenation `this.salt + this.fn` to it before taking its digest. The use of the terms `digest` and `salt` already reveal its probably a hash function and a quick look at the constructor reveals it is MD5 (which we can tell from the IV values in A,B,C and D and the structure of the `update` function):

```c
$[stack offset 3].constructor <- function ()
{
    this.A = 1732584193;
    this.B = 4023233417;
    this.C = 2562383102;
    this.D = 271733878;
    this.buf = this.blob();
    this.size = 0;
};
```

So from this `md5(key + filename)` digest we take 8 bytes and assign them to `header` and use the next 8 bytes as a value which is bitmasked and fet into `this.magic`. Note that here the decompiler screwed up and reports the bitmask to be `4294967295 = 0xFFFFFFFF` but it should be larger. It was, however, probably truncated by the decompiler using a 32-bit variable internally which we hadn't updated to a 64-bit one yet, a phenomenon which proved to be quite a pain throughout this reversing process. Either way taking a look at `magic` reveals it is a [linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator):

```c
$[stack offset 4].magic <- function ( x )
{
    // Function is a generator.
    while (true)
    {
        yield x;
        x = x * 3740067437 + 11;
        x = x & (1 << 48) - 1;
    }
};
```

Here, again, the multiplier `3740067437 = 0xDEECE66D` turned out to be a 32-bit truncation of the actual multiplier `0x5DEECE66D` which of course makes this the POSIX rand48 LCG with `multiplier = 0x5DEECE66D`, `addend = 0xB` and `modulus = 2**48`. Of interest here is that the function is a generator (which in squirrel is called when prefixed with `resume`) and it starts with a `yield` statement meaning the first value it will return is its seed, which is of help later on.

Now we can take a look at the `readblob` function which does the actual encryption:

```c
$[stack offset 4].readblob <- function ( size )
{
    local result = this.blob(0);

    if (size && !this.header.eos())
    {
        local t = this.header.readblob(size);
        size = size - t.len();
        result.writeblob(t);
    }

    if (size && !this.fileobj.eos())
    {
        local i = 0;
          // [030]  OP_JCMP           1        46    3    3

        if (this.fileobj.eos())
        {
        }
        else
        {
            if (this.pos == 0)
            {
                local rk = resume this.mana;
                  // [043]  OP_NEWOBJ         6         4    0    1
                $[stack offset 6].append($[stack offset 6], rk << 40);
                $[stack offset 6].append($[stack offset 6], rk << 32);
                $[stack offset 6].append($[stack offset 6], rk << 24);
                $[stack offset 6].append($[stack offset 6], rk << 16Press any key to continue . . . 
);
                this.cur = $[stack offset 6];
            }

            result.writen(this.fileobj.readn(98) ^ this.cur[this.pos], 98);
            this.pos = this.pos + 1 & 3;
            i++;
              // [076]  OP_JMP            0       -47    0    0
        }
    }

    return result;
};
```

We can see the `header` is written to the output (meaning the first 8 bytes of the file are the first 8 bytes of the `md5` digest) after which we iterate over the plaintext. A counter named `pos` is maintained which loops from 0 to 3 and whenever it is 0 it will tap the LCG, extract its value and construct a 4-element array consisting of the LCG value bitshifted with various values. The current plaintext byte is always XORed with the value in this array at index `pos`, making the encryption algorithm a simple streamcipher using the `rand48` LCG as its PRNG. Again a fault in the decompiler kicks in here since a keen eye will spot the senselessness of the leftwise bitshifts given that they only introduce nullbytes in the least significant bits of the value and we only use the least significant byte of each of those values. Hence we assumed this was a bug in the decompiler and changed the leftshifts to rightshifts.

Now we can put the above all together to start cracking the cipher:

* We know every 4 bytes of ciphertext are the result of 4 bytes of plaintext XORed with the least significant bytes of an array that looks like this `[(mana >> 40), (mana >> 32), (mana >> 24), (mana >> 16)]`

* Since we are dealing with a PNG file we can assume it has a fixed file header of 8 known bytes (being `"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"` and starting at offset 8 in the target file, after the md5 header) which allows us to use a known plaintext attack to derive 8 bytes of keystream using `xor(ciphertext[8:16], png_header)`

* The 8 bytes of keystream contain 2 (partial) LCG output values. We know the LCG outputs 48-bit values so we know:

```
keystream[0] = rk1[48..40]
keystream[1] = rk1[40..32]
keystream[2] = rk1[32..24]
keystream[3] = rk1[24..16]
keystream[4] = rk2[48..40]
keystream[5] = rk2[40..32]
keystream[6] = rk2[32..24]
keystream[7] = rk2[24..16]
```

Which means we have the upper 32 bits of LCG output 1 and 2 (dubbed rk1 and rk2) and miss the lower 16 bits. We can partially reconstruct `rk1` and `rk2` by reversing the bitshifts:

```python
rk1 = ((keystream[0] << 40) | (keystream[1] << 32) | (keystream[2] << 24) | (keystream[3] << 16))
rk2 = ((keystream[4] << 40) | (keystream[5] << 32) | (keystream[6] << 24) | (keystream[7] << 16))
```

* We also know `rk1` is the seed to the LCG so if we manage to fully reconstruct `rk1` we can clone the LCG and reproduce the full keystream to recover the original plaintext. We can recover `rk1` by brute-forcing its lower 16 bits and checking for which value `((lcg_step(rk1 | candidate) & 0xFFFFFFFF0000) == rk2)` holds, ie. which value is the preceding value to the second recovered LCG output.

Tying this all together in our [cracking script looks as follows](solution/sif_crack.py):

```python
#!/usr/bin/python
#
# BCTF 2016
# sif (REVERSING/350)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

import hashlib
from struct import pack, unpack

def magic_step(x):
    A = 0x5DEECE66D
    B = 0xB
    M = ((1 << 48) - 1)
    return (((x * A) + B) & M)

class magic:
    def __init__(self, seed):
        self.x = seed
        return

    def step(self):
        old_x = self.x
        self.x = magic_step(self.x)
        return old_x

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def recover_mana(keystream_slice):
    assert (len(keystream_slice) == 4)
    mana_lsbs = [ord(x) for x in list(keystream_slice)]
    return ((mana_lsbs[0] << 40) | (mana_lsbs[1] << 32) | (mana_lsbs[2] << 24) | (mana_lsbs[3] << 16))

def decrypt(ciphertext, seed):
    plaintext = ''
    pos = 0
    m = magic(seed)
    for i in xrange(len(ciphertext)):
        if (pos == 0):
            rk = m.step()
            cur = [(rk >> 40), (rk >> 32), (rk >> 24), (rk >> 16)]
        plaintext += chr(ord(ciphertext[i]) ^ (cur[pos] & 0xFF))
        pos = ((pos + 1) & 3)
    return plaintext

def mana_check(mana1, mana2):
    i = 0
    print "[*] Checking mana..."
    while(i < 2**16):
        candidate = (mana1 | i)
        if ((magic_step(candidate) & 0xFFFFFFFF0000) == (mana2 & 0xFFFFFFFF0000)):
            return candidate

        i += 1

    raise Exception("[-] Couldn't check LCG outputs...")
    return

ciphertext = open('flag.png', 'rb').read()
known_png_header = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
crypto_header = ciphertext[0:8]
cipher_png_header = ciphertext[8:8+len(known_png_header)]
keystream = xor_strings(cipher_png_header, known_png_header)

print "[+] crypto header: [%s]" % (crypto_header.encode('hex'))
print "[+] derived keystream: [%s]" % (keystream.encode('hex'))

mana1 = recover_mana(keystream[0:4])
mana2 = recover_mana(keystream[4:8])

print "[+] recovered (partial) LCG output 1: [%s]" % ('{:012x}'.format(mana1))
print "[+] recovered (partial) LCG output 2: [%s]" % ('{:012x}'.format(mana2))

seed = mana_check(mana1, mana2)

print "[+] cracked LCG seed: [%s]" % ('{:08x}'.format(seed))

open('plaintext_flag.png', 'wb').write(decrypt(ciphertext[8:], seed))
print "[+] decrypted flag.png!"
```

Which, when running, gives us:

```bash
$ ./sif_crack.py
[+] crypto header: [99c3f1d5f20c2317]
[+] derived keystream: [0c3e6181fdc88e94]
[+] recovered (partial) LCG output 1: [0c3e61810000]
[+] recovered (partial) LCG output 2: [fdc88e940000]
[*] Checking mana...
[+] cracked LCG seed: [c3e618181ea]
[+] decrypted flag.png!
```

Which yields a QR code image containing the flag:

```
BCTF{550_loveca_w1th0ut_UR}
```