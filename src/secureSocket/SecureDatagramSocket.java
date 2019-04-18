package secureSocket;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SecureDatagramSocket implements java.io.Closeable {

	private static final String CIPHERSUITE_CONFIG_PATH = "configs/server/ciphersuite.conf";
	private static final String TYPE_OF_KEYSTORE = "PKCS12";
	private static final String PATH_TO_KEYSTORE = "configs/keystore.p12";
	private static final String AES_256_KEY_ALIAS = "aes256-key";
	private static final String AES_256_MAC_KEY_ALIAS = "mac256-key";
	private static final String AES_128_MAC_KEY_ALIAS = "mac128-key";
	private static final String PASSWORD = "SRSC1819";
    
	private static final byte[] ivBytes = new byte[] {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };
   	
	private DatagramSocket socket;
	private Properties ciphersuit_properties;
	private Cipher cipher;
	private Mac hMac;
	private Mac hMacDoS;
	
	public SecureDatagramSocket(int port, InetAddress laddr) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		if( laddr.isMulticastAddress() ) {
			MulticastSocket ms = new MulticastSocket(port);
			ms.joinGroup(laddr);
			socket = ms;
		} else {
			socket = new DatagramSocket(port, laddr);
		}
		
		loadCipherSuitConfig();
		loadCipherSuit();
	}

	private void loadCipherSuit() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		
		// Load keystore
		KeyStore ks  = KeyStore.getInstance(TYPE_OF_KEYSTORE);
		ks.load(new FileInputStream(PATH_TO_KEYSTORE), PASSWORD.toCharArray());
		
		// Load Ciphersuit
		cipher = Cipher.getInstance(ciphersuit_properties.getProperty("session-ciphersuite"));
		cipher.init(Cipher.DECRYPT_MODE, readKey(ks, AES_256_KEY_ALIAS), new IvParameterSpec(ivBytes));
		
		// Load HMAC
		hMac = Mac.getInstance(ciphersuit_properties.getProperty("mac-key"));
		hMac.init(readKey(ks, AES_256_MAC_KEY_ALIAS));
		
		// Load HMAC for DoS
		hMacDoS = Mac.getInstance(ciphersuit_properties.getProperty("dos-mac-key"));
		hMacDoS.init(readKey(ks, AES_128_MAC_KEY_ALIAS));
	}

	private SecretKey readKey(KeyStore ks, String alias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(alias, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
		return entry.getSecretKey();
	}

	public SecureDatagramSocket(InetSocketAddress addr) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException {
		this(addr.getPort(), addr.getAddress());
	}

	public SecureDatagramSocket() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException {
		socket = new DatagramSocket();
		loadCipherSuitConfig();
		cipher = Cipher.getInstance(ciphersuit_properties.getProperty("session-ciphersuite"));
	}

	@Override
	public void close() throws IOException {
		socket.close();
	}

	public void receive(DatagramPacket p) throws IOException {
		socket.receive(p);
		decryptSecurePacket(p);
	}

	public void send(DatagramPacket p) throws IOException {
		encryptSecurePacket(p);
		socket.send(p);
	}

	// Porque estás a retornar bool?
	private boolean loadCipherSuitConfig() {
		try {
			InputStream inputStream = new FileInputStream(CIPHERSUITE_CONFIG_PATH);
			ciphersuit_properties = new Properties();
			ciphersuit_properties.load(inputStream);
			return true;
		} catch (IOException e) {	
			e.printStackTrace();
			return false;
		}
	}
	
	private void encryptSecurePacket(DatagramPacket p) {
		// TODO
	}
	
	private void decryptSecurePacket(DatagramPacket p) {
		// TODO
		
	}
}