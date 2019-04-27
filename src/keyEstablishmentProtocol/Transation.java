package keyEstablishmentProtocol;

import java.util.Base64;

public class Transation {
	private static final String SEPARATOR = ";";
	// {A, B, Na, Args, InnerMac_Ka}
	
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
	
	
}
