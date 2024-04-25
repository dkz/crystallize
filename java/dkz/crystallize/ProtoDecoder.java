package dkz.crystallize;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Objects;

/** Fail-fast event-based binary dump heap decoder. */
public final class ProtoDecoder {

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Builder() {}
        private ByteOrder order = ByteOrder.BIG_ENDIAN;
        private int maxStackBufferCapacity = 65536;
        private int maxStringBufferCapacity = 65536;
        private int maxInstanceBufferCapacity = 65536;

        /** Set byte order of the heap, JVM by default uses Big Endian. */
        public Builder setByteOrder(ByteOrder order) {
            this.order = order;
            return this;
        }
        /**
         * Adjust max capacity of the <em>stack buffer</em> in bytes.
         * Stack buffer stores stack trace frames and shouldn't be exceeded unless heap contains really long traces.
         */
        public Builder setMaxStackBufferCapacity(int capacity) {
            this.maxStackBufferCapacity = capacity;
            return this;
        }
        public Builder setMaxStringBufferCapacity(int capacity) {
            this.maxStringBufferCapacity = capacity;
            return this;
        }
        public Builder setMaxInstanceBufferCapacity(int capacity) {
            this.maxInstanceBufferCapacity = capacity;
            return this;
        }
        public ProtoDecoder build() {
            return new ProtoDecoder(
                    Objects.requireNonNull(order),
                    maxStackBufferCapacity,
                    maxStringBufferCapacity,
                    maxInstanceBufferCapacity);
        }
    }

    private final ByteOrder order;

    private ProtoDecoder(
            ByteOrder order,
            int maxStackBufferCapacity,
            int maxStringBufferCapacity,
            int maxInstanceBufferCapacity) {
        this.order = order;
        this.maxStackBufferCapacity = maxStackBufferCapacity;
        this.maxStringBufferCapacity = maxStringBufferCapacity;
        this.maxInstanceBufferCapacity = maxInstanceBufferCapacity;
        this.stackBuffer = ByteBuffer.allocate(16384).order(order);
        this.stringBuffer = ByteBuffer.allocate(16384).order(order);
        this.instanceBuffer = ByteBuffer.allocate(16384).order(order);
    }

    public void read(ReadableByteChannel channel, ProtoVisitor visitor) throws IOException {
        final ByteBuffer buffer = ByteBuffer.allocate(4096).order(order);
        channel.read(buffer);
        buffer.flip();
        StringBuilder header = new StringBuilder();
        for (byte b = buffer.get(); b != 0; b = buffer.get()) {
            header.append((char) b);
        }
        final Id id; {
            int i = buffer.getInt();
            switch (i) {
                case 4 -> { id = Id.u4; }
                case 8 -> { id = Id.u8; }
                default -> { throw new IOException("Unrecognized id size in the heap dump header: " + i); }
            }
        }
        long ts = buffer.getLong();
        visitor.visitHeader(header.toString(), id.size, ts);
        read(id, ByteChannels.buffered(buffer, channel), visitor);
    }

    private void read(Id id, ReadableByteChannel channel, ProtoVisitor visitor) throws IOException {

        records: while (true) {
            ByteBuffer header = borrow().limit(9);
            int read = channel.read(header);
            if (read < 9) {
                return;
            }
            header.flip();
            byte t = header.get();
            Tag tag = Tag.from(t);
            int time = header.getInt();
            int length = header.getInt();
            release(header);
            switch (tag) {
                case string -> { readString(id, channel, visitor, length); }
                case load_class -> { readLoadClass(id, channel, visitor); }
                case stack_frame -> { readStackFrame(id, channel, visitor); }
                case stack_trace -> { readStackTrace(id, channel, visitor); }
                case heap_dump -> {
                    ReadableByteChannel input = ByteChannels.frame(channel, length);
                    ByteBuffer buf = borrow();
                    input.read(buf);
                    buf.flip();
                    readHeapDump(id, new DataStream(input, buf), visitor);
                    release(buf);
                }
                case heap_dump_end -> {
                    break records;
                }
                default -> {
                    System.out.printf("unknown tag %x\n", t);
                    break records;
                }
            }
        }
    }

    private void readString(Id id, ReadableByteChannel channel, ProtoVisitor visitor, int length) throws IOException {
        ByteBuffer buf = readString(channel, length);
        long sid = id.read(buf);
        visitor.visitString(sid, StandardCharsets.UTF_8.decode(buf));
    }

    private void readLoadClass(Id id, ReadableByteChannel channel, ProtoVisitor visitor) throws IOException {
        ByteBuffer buf = read(channel, 2 * id.size + 8);
        int classSerial = buf.getInt();
        long classObjectId = id.read(buf);
        int stackSerial = buf.getInt();
        long classNameStringId = id.read(buf);
        release(buf);
        visitor.visitLoadClass(classSerial, classObjectId, stackSerial, classNameStringId);
    }

    private void readStackFrame(Id id, ReadableByteChannel channel, ProtoVisitor visitor) throws IOException {
        ByteBuffer buf = read(channel, 4 * id.size + 8);
        long stackFrameId = id.read(buf);
        long methodNameSid = id.read(buf);
        long methodSignatureSid = id.read(buf);
        long sourceSid = id.read(buf);
        int classSerial = buf.getInt();
        int location = buf.getInt();
        release(buf);
        visitor.visitStackFrame(
                stackFrameId,
                methodNameSid,
                methodSignatureSid,
                sourceSid,
                classSerial,
                location);
    }

    private void readStackTrace(Id id, ReadableByteChannel channel, ProtoVisitor visitor) throws IOException {
        ByteBuffer buf = read(channel, 12);
        int stackSerial = buf.getInt();
        int threadSerial = buf.getInt();
        int frames = buf.getInt();
        release(buf);
        ByteBuffer stack = readStack(channel, frames * id.size);
        long[] buffer = new long[frames];
        for (int j = 0; j < frames; j++) {
            buffer[j] = id.read(stack);
        }
        visitor.visitStackTrace(stackSerial, threadSerial, buffer);
    }

    private void readHeapDump(Id id, DataStream stream, ProtoVisitor visitor) throws IOException {
        while (stream.hasRemaining()) {
            HeapTag tag = HeapTag.from(stream.getByte());
            switch (tag) {
                case unknown -> {
                    long oid = stream.get(id);
                    visitor.visitRootUnknown(oid);
                }
                case root_jni_global -> {
                    long oid = stream.get(id);
                    long jni = stream.get(id);
                    visitor.visitRootJniGlobal(oid, jni);
                }
                case root_jni_local -> {
                    long oid = stream.get(id);
                    int threadSerial = stream.getInt();
                    int frameNumber = stream.getInt();
                    visitor.visitRootJniLocal(oid, threadSerial, frameNumber);
                }
                case root_java_frame -> {
                    long oid = stream.get(id);
                    int threadSerial = stream.getInt();
                    int frameNumber = stream.getInt();
                    visitor.visitRootJavaFrame(oid, threadSerial, frameNumber);
                }
                case root_native_stack -> {
                    long oid = stream.get(id);
                    int threadSerial = stream.getInt();
                    visitor.visitRootNativeStack(oid, threadSerial);
                }
                case root_sticky_class -> {
                    long oid = stream.get(id);
                    visitor.visitRootStickyClass(oid);
                }
                case root_thread_block -> {
                    long oid = stream.get(id);
                    int threadSerial = stream.getInt();
                    visitor.visitRootThreadBlock(oid, threadSerial);
                }
                case root_thread_object -> {
                    long oid = stream.get(id);
                    int threadSerial = stream.getInt();
                    int stackSerial = stream.getInt();
                    visitor.visitRootThreadObject(oid, threadSerial, stackSerial);
                }
                case root_monitor_used ->  {
                    long oid = stream.get(id);
                    visitor.visitRootMonitorUsed(oid);
                }
                case class_dump -> {
                    long cid = stream.get(id);
                    int stackSerial = stream.getInt();
                    long superCid = stream.get(id);
                    long loaderOid = stream.get(id);
                    long signerOid = stream.get(id);
                    long domainOid = stream.get(id);
                    long reserved1 = stream.get(id);
                    long reserved2 = stream.get(id);
                    int instanceSize = stream.getInt();
                    int constants = stream.getShort();
                    visitor.visitClassHeader(cid, stackSerial, superCid, loaderOid, signerOid, domainOid, instanceSize);
                    for (int j = 0; j < constants; j++) {
                        int index = stream.getShort();
                        switch (BasicType.from(stream.getByte())) {
                            case Object -> { visitor.visitClassConstantObject(cid, index, stream.get(id)); }
                            case Boolean -> { visitor.visitClassConstantBoolean(cid, index, stream.getBoolean()); }
                            case Char -> { visitor.visitClassConstantChar(cid, index, stream.getChar()); }
                            case Float -> { visitor.visitClassConstantFloat(cid, index, stream.getFloat()); }
                            case Double -> { visitor.visitClassConstantDouble(cid, index, stream.getDouble()); }
                            case Byte -> { visitor.visitClassConstantByte(cid, index, stream.getByte()); }
                            case Short -> { visitor.visitClassConstantShort(cid, index, stream.getShort()); }
                            case Int -> { visitor.visitClassConstantInt(cid, index, stream.getInt()); }
                            case Long -> { visitor.visitClassConstantLong(cid, index, stream.getLong()); }
                        }
                    }
                    int statics = stream.getShort();
                    for (int j = 0; j < statics; j++) {
                        long fieldNameSid = stream.get(id);
                        switch (BasicType.from(stream.getByte())) {
                            case Object -> { visitor.visitClassStaticObject(cid, fieldNameSid, stream.get(id)); }
                            case Boolean -> { visitor.visitClassStaticBoolean(cid, fieldNameSid, stream.getBoolean()); }
                            case Char -> { visitor.visitClassStaticChar(cid, fieldNameSid, stream.getChar()); }
                            case Float -> { visitor.visitClassStaticFloat(cid, fieldNameSid, stream.getFloat()); }
                            case Double -> { visitor.visitClassStaticDouble(cid, fieldNameSid, stream.getDouble()); }
                            case Byte -> { visitor.visitClassStaticByte(cid, fieldNameSid, stream.getByte()); }
                            case Short -> { visitor.visitClassStaticShort(cid, fieldNameSid, stream.getShort()); }
                            case Int -> { visitor.visitClassStaticInt(cid, fieldNameSid, stream.getInt()); }
                            case Long -> { visitor.visitClassStaticLong(cid, fieldNameSid, stream.getLong()); }
                        }
                    }
                    int fields = stream.getShort();
                    for (int j = 0; j < fields; j++) {
                        long fieldNameSid = stream.get(id);
                        switch (BasicType.from(stream.getByte())) {
                            case Object -> { visitor.visitClassFieldObject(cid, fieldNameSid); }
                            case Boolean -> { visitor.visitClassFieldBoolean(cid, fieldNameSid); }
                            case Char -> { visitor.visitClassFieldChar(cid, fieldNameSid); }
                            case Float -> { visitor.visitClassFieldFloat(cid, fieldNameSid); }
                            case Double -> { visitor.visitClassFieldDouble(cid, fieldNameSid); }
                            case Byte -> { visitor.visitClassFieldByte(cid, fieldNameSid); }
                            case Short -> { visitor.visitClassFieldShort(cid, fieldNameSid); }
                            case Int -> { visitor.visitClassFieldInt(cid, fieldNameSid); }
                            case Long -> { visitor.visitClassFieldLong(cid, fieldNameSid); }
                        }
                    }
                }
                case instance_dump -> {
                    long oid = stream.get(id);
                    int stackSerial = stream.getInt();
                    long cid = stream.get(id);
                    int size = stream.getInt();
                    ByteBuffer instance = getInstanceBuffer(size);
                    stream.read(instance);
                    visitor.visitInstance(oid, stackSerial, cid, instance);
                }
                case object_array_dump -> {
                    long oid = stream.get(id);
                    int stackSerial = stream.getInt();
                    int size = stream.getInt();
                    long cid = stream.get(id);
                    long[] ids = new long[size];
                    for (int j = 0; j < size; j++) {
                        ids[j] = stream.get(id);
                    }
                    visitor.visitObjectArray(oid, stackSerial, cid, ids);
                }
                case primitive_array_dump -> {
                    long oid = stream.get(id);
                    int stackSerial = stream.getInt();
                    int size = stream.getInt();
                    switch (BasicType.from(stream.getByte())) {
                        case Object -> {
                            throw new IOException("primitive object array");
                        }
                        case Boolean -> {
                            boolean[] arr = new boolean[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getBoolean();
                            }
                            visitor.visitBooleanArray(oid, stackSerial, arr);
                        }
                        case Char -> {
                            char[] arr = new char[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getChar();
                            }
                            visitor.visitCharArray(oid, stackSerial, arr);
                        }
                        case Float -> {
                            float[] arr = new float[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getFloat();
                            }
                            visitor.visitFloatArray(oid, stackSerial, arr);
                        }
                        case Double -> {
                            double[] arr = new double[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getDouble();
                            }
                            visitor.visitDoubleArray(oid, stackSerial, arr);
                        }
                        case Byte -> {
                            byte[] arr = new byte[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getByte();
                            }
                            visitor.visitByteArray(oid, stackSerial, arr);
                        }
                        case Short -> {
                            short[] arr = new short[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getShort();
                            }
                            visitor.visitShortArray(oid, stackSerial, arr);
                        }
                        case Int -> {
                            int[] arr = new int[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getInt();
                            }
                            visitor.visitIntArray(oid, stackSerial, arr);
                        }
                        case Long -> {
                            long[] arr = new long[size];
                            for (int j = 0; j < size; j++) {
                                arr[j] = stream.getLong();
                            }
                            visitor.visitLongArray(oid, stackSerial, arr);
                        }
                    }
                }
            }
        }
    }

    private record DataStream(ReadableByteChannel input, ByteBuffer buf) {

        boolean hasRemaining() throws IOException {
            if (!buf.hasRemaining()) read();
            return buf.hasRemaining();
        }

        int getInt() throws IOException {
            if (buf.remaining() < 4) read();
            return buf.getInt();
        }

        long getLong() throws IOException {
            if (buf.remaining() < 8) read();
            return buf.getLong();
        }

        short getShort() throws IOException {
            if (buf.remaining() < 2) read();
            return buf.getShort();
        }

        byte getByte() throws IOException {
            if (!buf.hasRemaining()) read();
            return buf.get();
        }

        char getChar() throws IOException {
            if (buf.remaining() < 2) read();
            return buf.getChar();
        }

        boolean getBoolean() throws IOException {
            if (buf.hasRemaining()) read();
            return buf.get() != 0;
        }

        float getFloat() throws IOException {
            if (buf.remaining() < 4) read();
            return buf.getFloat();
        }

        double getDouble() throws IOException {
            if (buf.remaining() < 8) read();
            return buf.getDouble();
        }

        long get(Id id) throws IOException {
            if (buf.remaining() < id.size) read();
            return id.read(buf);
        }

        void read(ByteBuffer dst) throws IOException {
            while (dst.remaining() > 0) {
                int required = dst.remaining();
                if (buf.remaining() < required) {
                    dst.put(buf);
                    read();
                    if (!buf.hasRemaining() && dst.hasRemaining()) {
                        throw new IOException();
                    }
                } else {
                    dst.put(dst.position(), buf, buf.position(), required);
                    buf.position(required + buf.position());
                    dst.position(required + dst.position());
                }
            }
        }

        void read() throws IOException {
            buf.compact();
            input.read(buf);
            buf.flip();
        }

    }

    private enum Id {
        u4(4) {
            @Override long read(ByteBuffer buf) {
                return buf.getInt();
            }
        },
        u8(8) {
            @Override long read(ByteBuffer buf) {
                return buf.getLong();
            }
        };
        abstract long read(ByteBuffer buf);
        final int size;
        Id(int size) {
            this.size = size;
        }
    }

    private enum BasicType {
        Object,
        Boolean,
        Char,
        Float,
        Double,
        Byte,
        Short,
        Int,
        Long;
        static BasicType from(byte bt) throws IOException {
            switch (bt) {
                case 2 -> { return Object; }
                case 4 -> { return Boolean; }
                case 5 -> { return Char; }
                case 6 -> { return Float; }
                case 7 -> { return Double; }
                case 8 -> { return Byte; }
                case 9 -> { return Short; }
                case 10 -> { return Int; }
                case 11 -> { return Long; }
                default -> throw new IOException(String.format("Unrecognized basic type: 0x%x", bt));
            }
        }
    }

    private enum Tag {
        string,
        load_class,
        stack_frame,
        stack_trace,
        heap_dump,
        heap_dump_end;
        static Tag from(byte bt) throws IOException {
            switch (bt) {
                case 0x01 -> { return string; }
                case 0x02 -> { return load_class; }
                case 0x04 -> { return stack_frame; }
                case 0x05 -> { return stack_trace; }
                case 0x1c -> { return heap_dump; }
                case 0x2c -> { return heap_dump_end; }
                default -> throw new IOException(String.format("Unrecognized heap record tag: 0x%x", bt));
            }
        }
    }

    private enum HeapTag {
        unknown,
        root_jni_global,
        root_jni_local,
        root_java_frame,
        root_native_stack,
        root_sticky_class,
        root_thread_block,
        root_monitor_used,
        root_thread_object,
        class_dump,
        instance_dump,
        object_array_dump,
        primitive_array_dump;
        static HeapTag from(byte bt) throws IOException {
            switch (bt) {
                case -1 -> { return unknown; }
                case 0x01 -> { return root_jni_global; }
                case 0x02 -> { return root_jni_local; }
                case 0x03 -> { return root_java_frame; }
                case 0x04 -> { return root_native_stack; }
                case 0x05 -> { return root_sticky_class; }
                case 0x06 -> { return root_thread_block; }
                case 0x07 -> { return root_monitor_used; }
                case 0x08 -> { return root_thread_object; }
                case 0x20 -> { return class_dump; }
                case 0x21 -> { return instance_dump; }
                case 0x22 -> { return object_array_dump; }
                case 0x23 -> { return primitive_array_dump; }
                default -> throw new IOException(String.format("Unrecognized heap record tag: 0x%x", bt));
            }
        }
    }

    /** Special buffer for collecting stack frames. */
    private ByteBuffer stackBuffer;
    private final int maxStackBufferCapacity;

    private ByteBuffer getStackBuffer(int size) {
        if (size > maxStackBufferCapacity) {
            throw new IllegalStateException(
                    "Exceeded max stack buffer capacity of "
                            + maxStackBufferCapacity
                            + ": stack buffer of "
                            + size
                            + " requested");
        }
        if (size <= stackBuffer.capacity()) {
            return stackBuffer.clear().limit(size);
        } else {
            int u = Integer.highestOneBit(size) << 1;
            return stackBuffer = ByteBuffer.allocate(u).order(order).limit(size);
        }
    }

    private ByteBuffer readStack(ReadableByteChannel channel, int length) throws IOException {
        ByteBuffer buf = getStackBuffer(length);
        int read = channel.read(buf);
        if (read < length) {
            throw new IOException(
                    "Expected at least "
                            + length
                            + " bytes available in the buffer");
        }
        return buf.flip();
    }

    /** Special buffer for collecting UTF8 strings. */
    private ByteBuffer stringBuffer;
    private final int maxStringBufferCapacity;

    private ByteBuffer getStringBuffer(int size) {
        if (size > maxStringBufferCapacity) {
            throw new IllegalStateException(
                    "Exceeded max string buffer capacity of "
                            + maxInstanceBufferCapacity
                            + ": string buffer of "
                            + size
                            + " requested");
        }
        if (size <= stringBuffer.capacity()) {
            return stringBuffer.clear().limit(size);
        } else {
            int u = Integer.highestOneBit(size) << 1;
            return stringBuffer = ByteBuffer.allocate(u).order(order);
        }
    }

    private ByteBuffer readString(ReadableByteChannel channel, int length) throws IOException {
        ByteBuffer buf = getStringBuffer(length);
        int read = channel.read(buf);
        if (read < length) {
            throw new IOException(
                    "Expected at least "
                            + length
                            + " bytes available in the buffer");
        }
        return buf.flip();
    }

    /** Special buffer used to expose a packed instance to the outside world. */
    private ByteBuffer instanceBuffer;
    private final int maxInstanceBufferCapacity;

    private ByteBuffer getInstanceBuffer(int size) {
        if (size > maxInstanceBufferCapacity) {
            throw new IllegalStateException(
                    "Exceeded max instance buffer capacity of "
                            + maxInstanceBufferCapacity
                            + ": instance buffer of "
                            + size
                            + " requested");
        }
        if (size <= instanceBuffer.capacity()) {
            return instanceBuffer.clear().limit(size);
        } else {
            int u = Integer.highestOneBit(size) << 1;
            return instanceBuffer = ByteBuffer.allocate(u).order(order).limit(size);
        }
    }

    /** Stack of small utility buffers, introduced to avoid excessive allocation. */
    private final ArrayList<ByteBuffer> bufferStack = new ArrayList<>();

    private ByteBuffer borrow() {
        if (!bufferStack.isEmpty()) {
            return bufferStack.remove(bufferStack.size() - 1).clear();
        } else {
            return ByteBuffer.allocate(4096).order(order);
        }
    }

    private void release(ByteBuffer buf) {
        bufferStack.add(buf);
    }

    private ByteBuffer read(ReadableByteChannel channel, int length) throws IOException {
        ByteBuffer buf = borrow().limit(length);
        int read = channel.read(buf);
        if (read < length) {
            throw new IOException(
                    "Expected at least "
                            + length
                            + " bytes available in the buffer");
        }
        return buf.flip();
    }

}
