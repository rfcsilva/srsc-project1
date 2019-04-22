package kdc;

public interface KDC {

	void /*request*/ receiveRequest();
	
	void sendReply(/*request ,*/ KDCReply reply); // TODO: e se uma das msgs se perde?
	
}
