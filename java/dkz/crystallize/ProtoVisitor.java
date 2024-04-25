package dkz.crystallize;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Exposes a method for each individual binary record or section in a heap file.
 * Proto decoder calls these in order of record occurrence.
 */
public interface ProtoVisitor {

    /**
     * @param header "JAVA PROFILE 1.0.2" string header
     * @param idSize size of identifiers (pointers) on the heap
     * @param ts timestamp of the heap
     */
    void visitHeader(String header, int idSize, long ts);

    /**
     * Reads a string from heap's string pool.
     * @param id string identifier
     * @param string character buffer with string contents
     */
    void visitString(long id, CharBuffer string);

    /**
     * @param cid class id
     * @param nameSid class name string id (refers to the string pool)
     */
    void visitLoadClass(int classSerial, long cid, int stackSerial, long nameSid);

    /**
     * @param stackFrameId id of the stack frame referred from stack trace
     * @param methodNameSid string identifier of the method name
     * @param methodSignatureSid string identifier of the method's signature
     * @param sourceSid source file name string id
     * @param lineNumber the line number within the source file or {@code -1}
     */
    void visitStackFrame(
            long stackFrameId,
            long methodNameSid,
            long methodSignatureSid,
            long sourceSid,
            int classSerial,
            int lineNumber);

    /**
     * @param frames array of stack frame ids that belong to this stack trace
     * @param threadSerial id of the running thread
     */
    void visitStackTrace(
            int stackSerial,
            int threadSerial,
            long[] frames);


    /**
     * Indicates that the object is pinned to GC roots for an unknown reason.
     * @param oid object id
     */
    void visitRootUnknown(long oid);

    /**
     * Indicates that the object is pinned to GC roots as a JNI global.
     * @param oid object id
     * @param globalReferenceId JNI global reference identifier
     */
    void visitRootJniGlobal(long oid, long globalReferenceId);

    /**
     * The object is pinned to GC roots as a JNI local.
     * @param oid object id
     * @param threadSerial id of the running thread
     * @param frameNumber frame number in the stack trace
     */
    void visitRootJniLocal(long oid, int threadSerial, int frameNumber);

    /**
     * Marks object as pinned to GC roots in a java stack frame.
     * @param oid object id
     * @param threadSerial id of the running thread
     * @param frameNumber frame number in the stack trace
     */
    void visitRootJavaFrame(long oid, int threadSerial, int frameNumber);

    /**
     * Marks object as pinned to GC roots from a native stack frame.
     * @param oid object id
     * @param threadSerial id of the running thread
     */
    void visitRootNativeStack(long oid, int threadSerial);

    void visitRootStickyClass(long oid);

    void visitRootThreadBlock(long oid, int threadSerial);

    /**
     * Object is used as monitor for synchronization, pinned to GC roots.
     * @param oid object id
     */
    void visitRootMonitorUsed(long oid);

    /**
     * A running thread object itself, pinned to GC roots.
     * @param oid object id
     * @param threadSerial id of the running thread
     */
    void visitRootThreadObject(long oid, int threadSerial, int stackSerial);

    /**
     * @param cid class id
     * @param superCid superclass class id
     * @param loaderOid class loader object id
     * @param signerOid signer object id
     * @param domainOid protection domain object id
     * @param instanceSize instance size in bytes
     */
    void visitClassHeader(
            long cid,
            int stackSerial,
            long superCid,
            long loaderOid,
            long signerOid,
            long domainOid,
            int instanceSize);

    void visitClassConstantObject(long cid, int index, long oid);
    void visitClassConstantBoolean(long cid, int index, boolean value);
    void visitClassConstantChar(long cid, int index, char value);
    void visitClassConstantFloat(long cid, int index, float value);
    void visitClassConstantDouble(long cid, int index, double value);
    void visitClassConstantByte(long cid, int index, byte value);
    void visitClassConstantShort(long cid, int index, short value);
    void visitClassConstantInt(long cid, int index, int value);
    void visitClassConstantLong(long cid, int index, long value);

    void visitClassStaticObject(long cid, long fieldNameSid, long oid);
    void visitClassStaticBoolean(long cid, long fieldNameSid, boolean value);
    void visitClassStaticChar(long cid, long fieldNameSid, char value);
    void visitClassStaticFloat(long cid, long fieldNameSid, float value);
    void visitClassStaticDouble(long cid, long fieldNameSid, double value);
    void visitClassStaticByte(long cid, long fieldNameSid, float value);
    void visitClassStaticShort(long cid, long fieldNameSid, short value);
    void visitClassStaticInt(long cid, long fieldNameSid, int value);
    void visitClassStaticLong(long cid, long fieldNameSid, long value);

    void visitClassFieldObject(long cid, long fieldNameSid);
    void visitClassFieldBoolean(long cid, long fieldNameSid);
    void visitClassFieldChar(long cid, long fieldNameSid);
    void visitClassFieldFloat(long cid, long fieldNameSid);
    void visitClassFieldDouble(long cid, long fieldNameSid);
    void visitClassFieldByte(long cid, long fieldNameSid);
    void visitClassFieldShort(long cid, long fieldNameSid);
    void visitClassFieldInt(long cid, long fieldNameSid);
    void visitClassFieldLong(long cid, long fieldNameSid);

    void visitObjectArray(long oid, int stackSerial, long cid, long[] ids);
    void visitBooleanArray(long oid, int stackSerial, boolean[] arr);
    void visitCharArray(long oid, int stackSerial, char[] arr);
    void visitFloatArray(long oid, int stackSerial, float[] arr);
    void visitDoubleArray(long oid, int stackSerial, double[] arr);
    void visitByteArray(long oid, int stackSerial, byte[] arr);
    void visitShortArray(long oid, int stackSerial, short[] arr);
    void visitIntArray(long oid, int stackSerial, int[] arr);
    void visitLongArray(long oid, int stackSerial, long[] arr);

    /**
     * @param oid object id
     * @param cid class id
     * @param instance byte buffer with instance fields packed
     */
    void visitInstance(
            long oid,
            int stackSerial,
            long cid,
            ByteBuffer instance);

}
