package kdc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.InetSocketAddress;

import cryptography.CryptographyUtils;

//TODO: renomear?
public class UDP_KDC_Server {

	public static void main(String[] args) throws FileNotFoundException {
		if(args.length < 2) {
			System.out.println("usage: kdc <ip> <port>");
		}
		//InputStream inputStream = new FileInputStream("configs/kdc/ciphersuite.conf");
		
		InetSocketAddress addr = new InetSocketAddress( args[0], Integer.parseInt(args[1]) );
		
		KDC kdc_server = new NeedhamSchroederKDC(addr);
		
		System.out.println("KDC Server ready to receive...");
		
		while(true) {
			// recebe pedidos -> não deveria bloquear infintamente? ou isto lança uma excepção? eu acho que lança ...
			kdc_server.receiveRequest();
			
			// gera cenas e faz o mambo
			//CryptographyUtils.
			KDCReply reply = new KDCReply(); //TODO
			
			// envia replys
			kdc_server.sendReply(reply);
		}
	}
}
