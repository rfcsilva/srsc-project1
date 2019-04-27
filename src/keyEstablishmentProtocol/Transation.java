package keyEstablishmentProtocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Base64;

import cryptography.CryptographyDoubleMac;
import secureSocket.exceptions.InvalidMacException;
import util.Utils;

public class Transation {
	private static final String SEPARATOR = ";";
	// {A, B, Na, Args, InnerMac_Ka}

	private static final String INVALID_INNER_MAC = "Invalid Inner Mac";

	private String a;
	private String b;
	private long na;
	private String[] args;
	private byte[] innerMac;

	public Transation(String a, String b, long na, String[] args, byte[] innerMac) {

		this.a = a;
		this.b = b;
		this.na = na;
		this.args = args;
		this.innerMac = innerMac;

	}

	public String toString() {

		String asString = a.concat(SEPARATOR).concat(b).concat(SEPARATOR);
		asString =  asString.concat(String.valueOf(na)).concat(SEPARATOR);
		for(String arg : args) {
			asString = asString.concat(arg).concat(SEPARATOR);
		}

		return asString.concat(Base64.getEncoder().encodeToString(innerMac));

	}

	public Transation fromString(String asString) {

		String[] parts = asString.split(SEPARATOR);
		String a = parts[0];
		String b = parts[1];
		long nc = Long.parseLong(parts[2]);

		String[] args = new String[ parts.length - 4];
		for(int i = 3; i < parts.length -1; i++) {
			args[i-3] = parts[i];
		}

		innerMac = Base64.getDecoder().decode(parts[parts.length-1]);

		return new Transation(a, b, nc, args, innerMac);
	}

	public byte[] serialize() throws IOException {

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(a);
		dataOut.writeUTF(b);
		dataOut.writeLong(na);

		dataOut.writeInt(args.length);
		for(String arg: args)
			dataOut.writeUTF(arg);

		dataOut.flush();
		byteOut.flush();

		byte[] data = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return Utils.concat(data, innerMac);
	}

	public static Transation deserialize(CryptographyDoubleMac cryptoManager, byte[] rawData) throws IOException, InvalidMacException, InvalidKeyException {

		byte[][] messageParts = cryptoManager.splitIntegrityProof(rawData);
		if (!cryptoManager.validateIntegrityProof(messageParts[0], messageParts[1]))
			throw new InvalidMacException(INVALID_INNER_MAC);
		else {

			ByteArrayInputStream byteIn = new ByteArrayInputStream(rawData);
			DataInputStream dataIn = new DataInputStream(byteIn);

			String a = dataIn.readUTF();
			String b = dataIn.readUTF();
			long na = dataIn.readLong();

			int length = dataIn.readInt();
			String[] arguments = new String[length];
			for(int i = 0; i < length; i++) {
				arguments[i] = dataIn.readUTF();
			}

			length = dataIn.readInt();
			byte[] innerMac = new byte[length];
			dataIn.read(innerMac, 0, length);

			dataIn.close();
			byteIn.close();

			return new Transation(a, b, na, arguments, innerMac);

		}
	}

	public String getA() {
		return a;
	}

	public String getB() {
		return b;
	}

	public long getNa() {
		return na;
	}

	public String[] getArgs() {
		return args;
	}

	public byte[] getInnerMac() {
		return innerMac;
	}
}
