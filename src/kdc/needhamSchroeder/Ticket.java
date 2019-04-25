package kdc.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Ticket {
	
	private long nc;
	private byte[]a, b, Ks;

	public Ticket(long nc, byte[] a, byte[] b, byte[] Ks) {
		this.nc = nc;
		this.a = a;
		this.b = b;
		this.Ks = Ks;
	}

	
	public byte[] serialize() throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(nc);
		dataOut.writeInt(a.length);
		dataOut.write(a, 0, a.length);
		dataOut.writeInt(b.length);
		dataOut.write(b, 0, b.length);
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
		
		int length = dataIn.readInt();
		byte[] a = new byte[length];
		dataIn.read(a, 0, length);
		
		length = dataIn.readInt();
		byte[] b = new byte[length];
		dataIn.read(b, 0, length);
		
		length = dataIn.readInt();
		byte[] ks = new byte[length];
		dataIn.read(ks, 0, length);
		
		return new Ticket(nc, a, b, ks);
		
	}

	public long getNc() {
		return nc;
	}

	public byte[] getA() {
		return a;
	}

	public byte[] getB() {
		return b;
	}

	public byte[] getKs() {
		return Ks;
	}

}
