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

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import cryptography.nonce.NonceManager;
import cryptography.nonce.WindowNonceManager;
import keyEstablishmentProtocol.KeyEstablishmentProtocolClient;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.InvalidChallangeReplyException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.TooManyTriesException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnServerException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.WrongCryptoManagerException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.WrongMessageTypeException;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.exceptions.ReplayedNonceException;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;
import util.Utils;

public class NeedhamSchroederClient implements KeyEstablishmentProtocolClient {

	private static final int TIMEOUT = 30*1000;

	private Cryptography master_cryptoManager;
	private InetSocketAddress kdc_addr;
	private InetSocketAddress a_addr;
	private int max_tries = 3;
	private String a;

	public NeedhamSchroederClient(InetSocketAddress kdc_addr, String a, Cryptography master_cryptoManager) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		this.kdc_addr = kdc_addr;
		this.master_cryptoManager = master_cryptoManager;
		this.a = a;
	}

	public void setMaxTries(int tries) {
		this.max_tries = tries;
	}

	public InetSocketAddress getMyAddr() {
		return a_addr;
	}

	@Override
	public Cryptography getSessionParameters(String b, String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidChallangeReplyException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, TooManyTriesException, UnkonwnIdException, UnkonwnServerException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, WrongCryptoManagerException {

		NonceManager nonceManager = new WindowNonceManager(master_cryptoManager.getSecureRandom());

		SecureDatagramSocket socket = new SecureDatagramSocket(master_cryptoManager);
		socket.setTimeout(TIMEOUT); 

		for(int i=0; i < max_tries; i++) {
			try {
				long Na = nonceManager.generateNonce();

				NS2 kdc_reply = requestKeys(socket, kdc_addr, Na, nonceManager, a, b, args);

				// Build the session cryptoManager
				Cryptography session_cryptoManager = CryptoFactory.deserializeSessionParameters(kdc_reply.getKs());

				InetSocketAddress b_addr = Utils.unparseAddr(kdc_reply.getBAddr());

				shareKeys(socket, session_cryptoManager, b_addr, kdc_reply.getTicket(), nonceManager);

				System.out.println("Finished key establishment.");

				this.a_addr = socket.getLocalAddress();

				socket.close();

				return session_cryptoManager;
			} catch (SocketTimeoutException e) {
				// Try again
			} catch (ReplayedNonceException | InvalidChallangeReplyException | WrongMessageTypeException e) {
				System.err.println(e.getMessage());
			} 
		}

		throw new TooManyTriesException("" + max_tries);
	}

	private NS2 requestKeys(SecureDatagramSocket socket, InetSocketAddress kdc_addr, long Na, NonceManager nonceManager, String a, String b, String[] args) throws IOException, InvalidChallangeReplyException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, ReplayedNonceException, UnkonwnIdException, WrongMessageTypeException, UnkonwnServerException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, WrongCryptoManagerException {
			socket.setCryptoManager(master_cryptoManager);

			System.out.println("Requesting keys... " + Na);
			//Payload ns1 = new NS1(a, b, Na, args, master_cryptoManager); 
			Payload ns1 = new NS1_Coins(a, b, Na, args, master_cryptoManager);
			SecureMessage sm = new SecureMessageImplementation(ns1);
			socket.send(sm, kdc_addr);

			// Receive reply from KDC
			socket.receive(sm);

			if(sm.getPayloadType() == NS2.TYPE) {
				NS2 reply = (NS2) sm.getPayload();

				if( nonceManager.verifyReplay(reply.getNc()) ) {
					throw new ReplayedNonceException("KDC nonce (Nc) was replayed: " + reply.getNc());
				} else if(reply.getNa_1() != Na+1) {
					throw new InvalidChallangeReplyException("KDC challenge answer is wrong. " + reply.getNa_1());
				} else
					System.out.println("Received Keys. " + (Na+1));

				return reply;
			} else if(sm.getPayloadType() == NS0.TYPE) {
				NS0 reply = (NS0) sm.getPayload();
				if(reply.getErrorCode() == ErrorCodes.UNKNOWN_SERVER.ordinal()) {
					throw new UnkonwnServerException(reply.getErrorMessage());
				}else if(reply.getErrorCode() == ErrorCodes.NOT_ENOUGH_MONEY.ordinal()){
					System.err.println(reply.getErrorMessage());					
				}
			} 				
			
			throw new WrongMessageTypeException("" + sm.getPayloadType());
	}  

	private void shareKeys(SecureDatagramSocket socket, Cryptography session_cryptoManager, InetSocketAddress b_addr, byte[] ticket, NonceManager nonceManager) throws IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, ReplayedNonceException, UnkonwnIdException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		socket.setCryptoManager(session_cryptoManager);

		Payload ns3 = new NS3(ticket, session_cryptoManager);

		System.out.println("Sending Ticket to B ...");
		SecureMessage sm = new SecureMessageImplementation(ns3);
		socket.send(sm, b_addr);

		// Receive Challenge
		sm = new SecureMessageImplementation();
		InetSocketAddress reply_addr = socket.receive(sm);
		long Nb =((NS4)sm.getPayload()).getNb();

		System.out.println("Received Challenge. " + Nb);

		if(!nonceManager.registerNonce(Nb)) {
			// Compute Reply
			long Nb_1 = (Nb + 1);

			System.out.println("Sending Challenge result ... " + Nb_1);
			NS4 ns4 = new NS4(Nb_1, session_cryptoManager);
			sm = new SecureMessageImplementation(ns4);
			socket.send(sm, reply_addr);
		} else {
			throw new ReplayedNonceException("B challenge was replayed: " + Nb);
		}
	}  

}

