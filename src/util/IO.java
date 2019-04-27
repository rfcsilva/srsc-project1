package util;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;

import keyEstablishmentProtocol.needhamSchroeder.Transation;

public class IO {

	private static final String DEFAULT_CHARSET = "utf-8";

	public synchronized static boolean write(Transation tsn, String filename, String charSet){

		if(charSet == null |  charSet.equals("") )
			charSet = DEFAULT_CHARSET;

		FileOutputStream fileOutStream;
		Writer writer = null;
		PrintWriter p_Writer;
		try {
			
			fileOutStream = new FileOutputStream(filename, true);
		    writer = new BufferedWriter(new OutputStreamWriter(fileOutStream, charSet));
		    p_Writer = new PrintWriter(writer, true);
		    System.out.println(tsn.toString());
			p_Writer.println(tsn.toString());
			
			return true;
		
		} catch (IOException e) {
			return false;
		} finally {
			try {
				writer.close();
			} catch (Exception e) {
				return false;
			}
		}
		
	}




}
