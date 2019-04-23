/*
* hjStreamServer.java 
* Streaming server: emitter of video streams (movies)
* Can send in unicast or multicast IP for client listeners
* that can play in real time the transmitted movies
*/

package server;

import java.io.*;
import java.net.*;

import javax.crypto.Cipher;

import cryptography.AbstractCryptography;
import cryptography.Cryptography;
import cryptography.CryptographyDoubleMac;
import secureSocket.SecureDatagramSocket;

class hjStreamServer {

	private static final String CIPHERSUITE_CONFIG_PATH = "configs/server/ciphersuite.conf";
	
	static public void main( String []args ) throws Exception {
	        if (args.length != 3)
	        {
	         System.out.println("Erro, usar: mySend <movie> <ip-multicast-address> <port>");
	         System.out.println("        or: mySend <movie> <ip-unicast-address> <port>");
	         System.exit(-1);
	         }
      
		int size;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(args[0]) );
		byte[] buff = new byte[65000];
		//MulticastSocket s = new MulticastSocket();
		//DatagramSocket s = new DatagramSocket();
		Cryptography cryptoManager = AbstractCryptography.loadFromConfig(CIPHERSUITE_CONFIG_PATH);
		SecureDatagramSocket socket = new SecureDatagramSocket(cryptoManager);
		InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); // tempo de referencia para este processo
		long q0 = 0;
		
		while ( g.available() > 0 ) {
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			socket.send( p );
			System.out.print( "." );
		}
		
		g.close();
		socket.close();

		System.out.println("DONE! packets sent: "+count);
	}

}
