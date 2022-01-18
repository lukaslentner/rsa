package rsa.padding;

import java.io.IOException;
import java.io.InputStream;

public class PaddingInputStream extends InputStream {
	
	public static final int ESCAPE_BYTE = 4;
	
	public static final int PADDING_BYTE = 5;
	
	private final InputStream innerStream;
	
	private final Integer wordSize;
	
	private int escaped;
	
	private int length;
	
	public PaddingInputStream(final InputStream innerStream, final Integer wordSize) {
		this.innerStream = innerStream;
		this.wordSize = wordSize;
		this.escaped = -1;
		this.length = 0;
	}

	@Override
	public int read() throws IOException {
		
		if(this.escaped >= 0) {
			final int result = this.escaped;
			this.escaped = -1;
			this.increaseLength();
			return result;
		}
		
		final int innerResult = this.innerStream.read();
		
		if(innerResult == ESCAPE_BYTE || innerResult == PADDING_BYTE) {
			this.escaped = innerResult;
			this.increaseLength();
			return ESCAPE_BYTE;
		}
		
		if(innerResult == -1) {
			if(this.length == 0) {
				return -1;
			} else {
				this.increaseLength();
				return PADDING_BYTE;
			}
		}
		
		this.increaseLength();
		return innerResult;
	
	}

	private void increaseLength() {
		this.length = (this.length + 1) % this.wordSize;
	}
	
}
