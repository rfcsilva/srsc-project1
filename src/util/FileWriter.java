package util;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;

import keyEstablishmentProtocol.Transation;

public class FileWriter {

	private static final String DEFAULT_CHARSET = "utf-8";

	public synchronized static boolean write(Transation tsn, String filename, String charSet){

		Writer writer = null;

		if(charSet == null |  charSet.equals("") )
			charSet = DEFAULT_CHARSET;

		FileOutputStream fileOutStream;

		try {
			fileOutStream = new FileOutputStream(filename, true);
			writer = new BufferedWriter(new OutputStreamWriter(fileOutStream, charSet));
			writer.write(tsn.toString());
			return true;

		} catch (IOException e) {
			return false;
		} finally {
			try {
				writer.close();
			} catch (IOException e) {
				return false;
			}
		}	
	}




}
