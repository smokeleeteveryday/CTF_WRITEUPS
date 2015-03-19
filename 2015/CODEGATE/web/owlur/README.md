# CodeGate General CTF 2015: Owlur

**Category:** Web
**Points:** 400
**Description:** 

## Write-up

The challenge was a basic PHP web application, the index.php tells us that this is an image sharing site for owl pictures and there's an upload box on the page.
After some quick investigation the following php files come up:

- **index.php**:
A page showing an upload form and a picture of an owl, telling us that this is supposed to be an image sharing sites for owls. 
Index.php takes a parameter called 'page'. 

- **view.php**:
takes a parameter 'id' which corresponds to a filename on the webserver. View.php simply prints the $_GET['id'] param unsanitized, which gives us an XSS vulnerability. 
This XSS is probably a decoy though. 

- **upload.php**:
Upload.php allows us to upload an image. The only check being done is if the extension is .jpg and if so, a random filename will be generated
and the uploaded file will be stored as <random>.jpg in /owls/


I immediately tested the page parameter for local file inclusion by testing if a prepended './' would still include the same file and sure enough it did. 
So i now have a local file inclusion vulnerability, but what can i actually include? The intended values for the page parameter were 'view' and 'upload' so it's very likely .php is appended somewhere. 

A nullbyte (%00) used to work as a string terminator in older PHP-versions which would allow us to sort of discard this appended .php string but as slightly expected, nullbyte injection did not work here. 

We need to find another route. What about uploading php in some file? Tests show out we can only upload .jpg files so maybe there's something different we're supposed to do with the file inclusion. 
Luckily i rememberd about how PHP filters could be 'abused' to disclose arbitrary local files on the filesystem via local file inclusion but it has a major drawback: 
it only works if you have complete control of the start of the string going into include(); or require();. Worth a try though.. 

Turns out that you could read files by injecting:
 
`php://filter/convert.base64-encode/resource=upload`

and 

`php://filter/convert.base64-encode/resource=view`

into the ?page param, which gave me the (base64-encoded) source code of the view and upload files. For some reason index.php didn't work (after the CTF i learned this was due to a moderation on the part of CodeGate). 

Reading the source did not give me any new clues though about how to get code execution (or get the flag via some other way). 
The only usefull info was the exact folder names the files are stored in (/var/www/owlur/owlur-zzzzzz/<RANDOMID>.jpg) and a confirmation of the limit file upload to .jpg extension and rename to random filename, so i hit a dead end. 

Intrigued by the fact that the local file disclosure with php://filter did work, i started to read up on 
other php filters and wrappers. I encountered http://php.net/manual/en/wrappers.compression.php which talks about a wrapper called zip:// with some very convenient syntax, namely:

`zip://archive.zip#dir/file.txt`

This means that we might be able to inject something like 

`zip://path/to/archive.jpg#file`

which gets '.php' appended and includes our uploaded and zipped file. I quickly tested this by zipping a test.php with phpinfo();, renaming it to .jpg and uploading it. 
Then, triggering the local file inclusion with the payload (%23 is an url-encoded #):

`index.php?page=zip:///var/www/owlur/owlur-zzzzzz/<RANDOM>.jpg%23test`

and i was greeted with a nice phpinfo(); output. Nice, we have code execution. Now finding the flag.

By uploading a simple php shell i found out that system() and passthru() are both disabled, so i just went on to look for the flag on the filesystem. 
Quickly whipped up a script to scandir(); and readfile(); dirs and files based on input and by listing the root directory '/' i immediately noticed the OWLUR-FLAG.txt. 

Reading this file (/OWLUR-FLAG.txt) gave me the flag: 
PHP fILTerZ aR3 c00l buT i pr3f3r f1lt3r 0xc0ffee


I
