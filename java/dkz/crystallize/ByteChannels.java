package dkz.crystallize;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.Objects;

public class ByteChannels {
    private ByteChannels() {}

    /** Pairs a byte channel with a buffer by prepending the buffer in front. */
    public static ReadableByteChannel buffered(ByteBuffer buffer, ReadableByteChannel backend) {
        return new Buffered(
                Objects.requireNonNull(buffer),
                Objects.requireNonNull(backend));
    }

    /**
     * Sets a hard byte count limit to the source byte channel.
     * Make sure to NOT read from source before frame is drained.
     */
    public static ReadableByteChannel frame(ReadableByteChannel backend, int size) {
        return new Frame(Objects.requireNonNull(backend), size);
    }

    private static final class Buffered implements ReadableByteChannel {

        private final ByteBuffer buffer;
        private final ReadableByteChannel backend;

        private Buffered(ByteBuffer buffer, ReadableByteChannel backend) {
            this.buffer = buffer;
            this.backend = backend;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            int read = 0;
            while (dst.remaining() > 0) {
                int required = dst.remaining();
                if (!buffer.hasRemaining()) {
                    buffer.clear();
                    if (backend.read(buffer) < 0) {
                        if (read > 0) {
                            return read;
                        } else {
                            return -1;
                        }
                    }
                    buffer.flip();
                }
                int remain = buffer.remaining();
                if (required >= remain) {
                    read += remain;
                    dst.put(buffer);
                } else {
                    dst.put(dst.position(), buffer, buffer.position(), required);
                    buffer.position(required + buffer.position());
                    dst.position(required + dst.position());
                    read += required;
                }
            }
            return read;
        }

        @Override
        public boolean isOpen() {
            return backend.isOpen();
        }

        @Override
        public void close() throws IOException {
            backend.close();
        }

    }

    private static final class Frame implements ReadableByteChannel {

        private int remaining;
        private final ReadableByteChannel backend;

        private Frame(ReadableByteChannel backend, int size) {
            this.remaining = size;
            this.backend = backend;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            final int read;
            if (remaining > dst.remaining()) {
                read = backend.read(dst);
            } else {
                int limit = dst.limit();
                try {
                    dst.limit(remaining + dst.position());
                    read = backend.read(dst);
                } finally {
                    dst.limit(limit);
                }
            }
            remaining = remaining - read;
            return read;
        }

        @Override
        public boolean isOpen() {
            return backend.isOpen();
        }

        @Override
        public void close() throws IOException {
            backend.close();
        }

    }
}
