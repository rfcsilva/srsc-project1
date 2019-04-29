package secureSocket.secureMessages;

public abstract class AbstractPayload implements Payload {

	protected long t1;
	protected long t2;
	
	public AbstractPayload() {
	}
	
	public AbstractPayload(long t1, long t2) {
		setTimestamps(t1, t2);
	}
	
	@Override
	public long[] getTimestamps() {
		return new long[] {t1, t2};
	}

	@Override
	public void setTimestamps(long t1, long t2) {
		this.t1 = t1;
		this.t2 = t2;
	}

}
