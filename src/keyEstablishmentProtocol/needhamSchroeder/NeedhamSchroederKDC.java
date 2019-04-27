package keyEstablishmentProtocol.needhamSchroeder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptoFactory;
import cryptography.nonce.NonceManager;
import cryptography.nonce.WindowNonceManager;
import keyEstablishmentProtocol.KeyEstablishmentProtocolKDC;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;
import util.IO;

public class NeedhamSchroederKDC implements KeyEstablishmentProtocolKDC {

	private static final String ERROR_WRTING_ON_FILE = "Error Wrting on file.";
	private static final int WINDOW_SIZE = 100;
	private static final String FILE_PATH = "./configs/kdc/log.txt";
	private static final String CHARSET = "utf-8";
	private SecureDatagramSocket socket;
	private NonceManager nonceManager;
	private String configPath;
	
	private Map<String, String> services;

	public NeedhamSchroederKDC(InetSocketAddress addr, CryptographyNS cryptoManager, String configPath, String servicesPath) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		socket = new SecureDatagramSocket(addr, cryptoManager);
		this.nonceManager = new WindowNonceManager(WINDOW_SIZE, cryptoManager.getSecureRandom());
		this.configPath = configPath;
		
		this.services = loadServices(servicesPath);
	}

	private Map<String, String> loadServices(String servicesPath) throws IOException {
		//Load file
		Properties services_properties = CryptoFactory.loadFile(servicesPath);
		Map<String, String> services = new HashMap<>(services_properties.size());
		
		services_properties.forEach( (k,v) -> services.put((String)k, (String)v));
		
		return services;
	}

	@Override
	public void start() throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchProviderException, IOException, InvalidPayloadTypeException, BrokenBarrierException {
		while(true) {
			SecureMessage sm = new SecureMessageImplementation();
			InetSocketAddress client_addr = receiveRequest(sm);
			processRequest(sm, client_addr, configPath);
		}
	}

	private void processRequest(SecureMessage request, InetSocketAddress client_addr, String configPath) {

		new Thread(() -> {
			try {
				//NS1 req = (NS1)request.getPayload();
				NS1_Coins req = (NS1_Coins)request.getPayload();
				String a = req.getA();
				String b = req.getB();
				long Na = req.getNa();

				if(this.verifyReplay(Na)) {
					System.err.println("Receveid replay " + Na);
				} else {
					System.out.println("Received request from " + a + "(" + client_addr.toString() + ")" + " to " + b + " with nonce " + Na);

					SecureDatagramSocket new_socket = new SecureDatagramSocket(req.getCryptoManagerA());

					// Generate Session Parameters for A and B
					byte[] securityParams = CryptoFactory.buildSessionParameters(configPath);

					if(!IO.write(req.getTransation(), FILE_PATH, CHARSET))
						System.err.println(ERROR_WRTING_ON_FILE);
					
					// Send reply to A
					long Na_1 = req.getNa() + 1;
					long Nc = this.getNonce();
					
					Payload payload = null;
					String server_addr = services.get(b);
					if(server_addr != null) {
						payload = new NS2(Na_1, Nc, securityParams, a, b, server_addr, req.getArgs(), req.getCryptoManagerB(), req.getCryptoManagerA());
					} else {
						payload = new NS0(ErrorCodes.UNKNOWN_SERVER.ordinal(), "Unknown Server " + b, req.getCryptoManagerA());
					}
					SecureMessage sm = new SecureMessageImplementation(payload);
					new_socket.send(sm, client_addr);
				}

			} catch(Exception e) {
				e.printStackTrace();
			}
		}).start();
	}

	public InetSocketAddress receiveRequest( SecureMessage sm ) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException {
		InetSocketAddress addr = null;

		boolean replay = false, unknown = false;
		do {
			try {
				addr = socket.receive(sm);

				// Verify if is replay
				long Na = ((NS1_Coins)sm.getPayload()).getNa();
				replay = this.verifyReplay(Na);
				if(replay)
					System.err.println("Replayed request " + Na);
			} catch(UnkonwnIdException e) {
				System.err.println("Unknown id: " + e.getMessage());
				unknown = true;
			}
		} while(replay || unknown);

		return addr;	
	}

	private synchronized long getNonce() {
		return nonceManager.generateNonce();
	}

	private synchronized boolean verifyReplay(long nonce) {
		return nonceManager.verifyReplay(nonce);
	}
}
