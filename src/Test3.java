import java.security.Key;
import java.security.KeyStore.Entry.Attribute;
import java.util.Properties;

import javax.crypto.SecretKey;

import cryptography.CryptoFactory;
import util.arKeyStore;

public class Test3 {

	public static void main(String[] args) throws Exception {
		Properties props = CryptoFactory.loadFile("./configs/proxy/ciphersuite.conf");
		String path = "./configs/kdc/kdc-keystore.p12";
		String path2 = "./configs/server/b-keystore.p12";
		String password = "SRSC1819";
		String type = "PKCS12";
		arKeyStore ks = new arKeyStore(path, password, type);
		arKeyStore ks2 = new arKeyStore(path2, password, type);
		
		SecretKey[] keys = CryptoFactory.genKeysFromPassword("", props);
		
		String id = "movie-server";
		
		ks.setKey("k" + id, keys[0]);
		ks.setKey("km" + id, keys[1]);
		
		ks.store();
		
		ks2.setKey("k" + id, keys[0]);
		ks2.setKey("km" + id, keys[1]);
		
		ks2.store();
		

		/*for( String s : ks.aliases() ) {
			System.out.print(s + " ");
			/*for( Attribute a : ks.getEntry(s).getAttributes() ) {
				System.out.print(a.getName() + ":" + a.getValue());
			}*/
			/*
			
			System.out.print(ks.getKey(s).getAlgorithm() + " ");
			System.out.print(ks.getKey(s).getFormat() + " ");
			System.out.print(ks.getKey(s).getEncoded().length + " bytes" + " " + (ks.getKey(s).getEncoded().length*8) + " bits" + " ");
			
			System.out.println("");
		}*/
		
		/*SecretKey kc = CryptoFactory.generateKey("AES", 256);
		SecretKey kmc = CryptoFactory.generateKey("AES", 256);
		
		ks.setKey("kc", kc);
		ks.setKey("kmc", kc);*/
		
		for( String s : ks.aliases() ) {
			System.out.println(s);
		}
		
		System.out.println("\n\n");
		
		for( String s : ks2.aliases() ) {
			System.out.println(s);
		}
		
		//ks.store();
	}

}
