package keyEstablishmentProtocol.needhamSchroeder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.asn1.cms.TimeStampAndCRL;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import cryptography.nonce.WindowNonceManager;
import cryptography.time.Timestamp;
import keyEstablishmentProtocol.KeyEstablishmentProtocolServer;
import keyEstablishmentProtocol.RequestHandler;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class NeedhamSchroederServer implements KeyEstablishmentProtocolServer {

	private static final int DEFAULT_TIMEOUT = 30 * 1000;

	private InetSocketAddress b_addr;
	private Cryptography master_cryptoManager;
	private WindowNonceManager nonceManager;

	public NeedhamSchroederServer(InetSocketAddress b_addr, Cryptography master_cryptoManager)
			throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
			CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException,
			ShortBufferException, IllegalBlockSizeException, BadPaddingException {

		this.b_addr = b_addr;
		this.master_cryptoManager = master_cryptoManager;
		this.nonceManager = new WindowNonceManager(master_cryptoManager.getSecureRandom());
	}

	@Override
	public void start(RequestHandler requestHandler)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException,
			InvalidPayloadTypeException, BrokenBarrierException, UnkonwnIdException {

		// Listen for incoming requests
		listenRequests(master_cryptoManager, requestHandler);
	}

	private void listenRequests(Cryptography master_cryptoManager, RequestHandler requestHandler) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, 
			UnrecoverableEntryException, KeyStoreException,	CertificateException, IOException, ShortBufferException, 
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, UnkonwnIdException {

				SecureDatagramSocket inSocket = new SecureDatagramSocket(b_addr, master_cryptoManager);

				System.out.println("Waitting for Ticket...");

				while (true) {
					try {
						// Receive Ticket
						SecureMessage sm = new SecureMessageImplementation();
						InetSocketAddress addr = inSocket.receive(sm);

						System.out.println("Received Ticket.");

						NS3 ns3 = (NS3) sm.getPayload();

						// If not replay
						if (!verifyReplay(ns3.getNc()))
							processRequest(ns3, addr, requestHandler);
						else
							System.err.println("Replay of: " + ns3.getNc());

					} catch (SocketTimeoutException e) {}
				}

				//inSocket.close();
	}

	private void processRequest(NS3 ns3, InetSocketAddress addr, RequestHandler requestHandler) {
		new Thread(() -> {
			try {
				
				Cryptography session_cryptoManager = CryptoFactory.deserializeSessionParameters( ns3.getKs() ); 

				SecureDatagramSocket new_socket = new SecureDatagramSocket(session_cryptoManager);
				new_socket.setTimeout(DEFAULT_TIMEOUT);

				long Nb = getNonce();
				long[] timeStamps = Timestamp.getTimeInterval();
				
				NS4 ns4 = new NS4(Nb, timeStamps[0], timeStamps[1], session_cryptoManager);
				SecureMessage sm = new SecureMessageImplementation(ns4);
				new_socket.send(sm, addr);
				System.out.println("Sending Challenge... " + Nb);

				SecureMessage sm2 = new SecureMessageImplementation();
				InetSocketAddress client_addr = new_socket.receive(sm2);
				
				NS4 ns5 = (NS4) sm2.getPayload();

				if (ns5.getNb() == (Nb + 1)) {
					System.out.println("Valid Challenge Answer: " + ns5.getNb());
					
					if(requestHandler != null)
						requestHandler.execute(new_socket, client_addr, ns3.getArgs());
					
				} else {
					System.err.println("Invalid Challenge Answer: " + ns5.getNb() + " != " + (Nb + 1));
				}
				
				if(!new_socket.isClosed())
					new_socket.close();

			} catch (Exception e) {
				//e.printStackTrace();
			}
		}).start();
	}

	private synchronized long getNonce() {
		return this.nonceManager.generateNonce();
	}

	private synchronized boolean verifyReplay(long nonce) {
		return this.nonceManager.verifyReplay(nonce);
	}

}
