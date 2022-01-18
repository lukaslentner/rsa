package rsa.padding;

import java.io.IOException;
import java.io.OutputStream;

public class DepaddingOutputStream extends OutputStream {
	
	private final OutputStream innerStream;
	
	private boolean lastEscaped;
	
	public DepaddingOutputStream(final OutputStream innerStream) {
		this.innerStream = innerStream;
		this.lastEscaped = false;
	}
	
	@Override
	public void write(int value) throws IOException {
		
		if (this.lastEscaped) {
			this.lastEscaped = false;
			this.innerStream.write(value);
			return;
		}
		
		if (value == PaddingInputStream.ESCAPE_BYTE) {
			this.lastEscaped = true;
			return;
		}
		
		if (value == PaddingInputStream.PADDING_BYTE) {
			// Do nothing
			return;
		}
		
		this.innerStream.write(value);
	
	}
	
}
