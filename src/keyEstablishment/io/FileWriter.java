package keyEstablishment.io;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;

import keyEstablishmentProtocol.Transation;

public class FileWriter {

	private static final String DEFAULT_CHARSET = "utf-8";
	
	public static void write(Transation tsn, String filename, String charSet) throws IOException {
		
		Writer writer = null;
 
		if(charSet == null |  charSet.equals("") )
			charSet = DEFAULT_CHARSET;
		
		try {
		    writer = new BufferedWriter(new OutputStreamWriter(
		          new FileOutputStream(filename), charSet));
		    writer.write(tsn.toString());
		} finally {
		   writer.close();
		 }	
	}
	
	
	

}
