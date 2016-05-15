
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



