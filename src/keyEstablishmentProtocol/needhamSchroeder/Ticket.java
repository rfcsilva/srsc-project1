package keyEstablishmentProtocol.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Ticket {
	
	private long nc;
	private byte[] Ks;
	private String a, b;
	private String[] arguments;
	private long t1;
	private long t2;

	public Ticket(long nc, String a, String b, byte[] Ks, String[] arguments, long t1, long t2) {
		this.nc = nc;
		this.a = a;
		this.b = b;
		this.Ks = Ks;
		this.t1 = t1;
		this.t2 = t2;
		
		this.arguments = (arguments == null ) ? new String[0] : arguments;
	}
	
	public byte[] serialize() throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(nc);
		
		dataOut.writeUTF(a);
		dataOut.writeUTF(b);
		
		dataOut.writeLong(t1);
		dataOut.writeLong(t2);;
		
		dataOut.writeInt(Ks.length);
		dataOut.write(Ks, 0, Ks.length);
		
		dataOut.writeInt(arguments.length);
		for(int i = 0; i < arguments.length; i++) {
			dataOut.writeUTF(arguments[i]);
		}

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
		
		long t1 = dataIn.readLong();
		long t2 = dataIn.readLong();

		int length = dataIn.readInt();
		byte[] ks = new byte[length];
		dataIn.read(ks, 0, length);
		
		length = dataIn.readInt();
		String[] arguments = new String[length];
		for(int i = 0; i < length; i++) {
			arguments[i] = dataIn.readUTF();
		}
		
		return new Ticket(nc, a, b, ks, arguments, t1, t2);
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

	public String[] getArgs() {
		return arguments;
	}
	
	public long t1() {
		return t1;
	}
	
	public long t2() {
		return t2;
	}

}
