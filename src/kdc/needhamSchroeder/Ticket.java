package kdc.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Ticket {
	
	private long nc;
	private byte[] Ks;
	private String a, b;

	public Ticket(long nc, String a, String b, byte[] Ks) {
		this.nc = nc;
		this.a = a;
		this.b = b;
		this.Ks = Ks;
	}
	
	public byte[] serialize() throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(nc);
		
		dataOut.writeUTF(a);
		dataOut.writeUTF(b);
		
		dataOut.writeInt(Ks.length);
		dataOut.write(Ks, 0, Ks.length);

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();
		
		return msg;
		
	}
	
	public static Ticket deserialize(byte[] rawdata) throws IOException {
		
		
		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawdata);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		long nc = dataIn.readLong();
		
		String a = dataIn.readUTF();
		String b = dataIn.readUTF();

		int length = dataIn.readInt();
		byte[] ks = new byte[length];
		dataIn.read(ks, 0, length);
		
		return new Ticket(nc, a, b, ks);
	}

	public long getNc() {
		return nc;
	}

	public String getA() {
		return a;
	}

	public String getB() {
		return b;
	}

	public byte[] getKs() {
		return Ks;
	}

}
