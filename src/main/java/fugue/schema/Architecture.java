// automatically generated by the FlatBuffers compiler, do not modify

package fugue.schema;

import java.nio.*;
import java.lang.*;
import java.util.*;
import com.google.flatbuffers.*;

@SuppressWarnings("unused")
public final class Architecture extends Table {
  public static void ValidateVersion() { Constants.FLATBUFFERS_2_0_0(); }
  public static Architecture getRootAsArchitecture(ByteBuffer _bb) { return getRootAsArchitecture(_bb, new Architecture()); }
  public static Architecture getRootAsArchitecture(ByteBuffer _bb, Architecture obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__assign(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public void __init(int _i, ByteBuffer _bb) { __reset(_i, _bb); }
  public Architecture __assign(int _i, ByteBuffer _bb) { __init(_i, _bb); return this; }

  public String processor() { int o = __offset(4); return o != 0 ? __string(o + bb_pos) : null; }
  public ByteBuffer processorAsByteBuffer() { return __vector_as_bytebuffer(4, 1); }
  public ByteBuffer processorInByteBuffer(ByteBuffer _bb) { return __vector_in_bytebuffer(_bb, 4, 1); }
  public boolean endian() { int o = __offset(6); return o != 0 ? 0!=bb.get(o + bb_pos) : false; }
  public long bits() { int o = __offset(8); return o != 0 ? (long)bb.getInt(o + bb_pos) & 0xFFFFFFFFL : 0L; }
  public String variant() { int o = __offset(10); return o != 0 ? __string(o + bb_pos) : null; }
  public ByteBuffer variantAsByteBuffer() { return __vector_as_bytebuffer(10, 1); }
  public ByteBuffer variantInByteBuffer(ByteBuffer _bb) { return __vector_in_bytebuffer(_bb, 10, 1); }
  public int auxiliary(int j) { int o = __offset(12); return o != 0 ? bb.get(__vector(o) + j * 1) & 0xFF : 0; }
  public int auxiliaryLength() { int o = __offset(12); return o != 0 ? __vector_len(o) : 0; }
  public ByteVector auxiliaryVector() { return auxiliaryVector(new ByteVector()); }
  public ByteVector auxiliaryVector(ByteVector obj) { int o = __offset(12); return o != 0 ? obj.__assign(__vector(o), bb) : null; }
  public ByteBuffer auxiliaryAsByteBuffer() { return __vector_as_bytebuffer(12, 1); }
  public ByteBuffer auxiliaryInByteBuffer(ByteBuffer _bb) { return __vector_in_bytebuffer(_bb, 12, 1); }

  public static int createArchitecture(FlatBufferBuilder builder,
      int processorOffset,
      boolean endian,
      long bits,
      int variantOffset,
      int auxiliaryOffset) {
    builder.startTable(5);
    Architecture.addAuxiliary(builder, auxiliaryOffset);
    Architecture.addVariant(builder, variantOffset);
    Architecture.addBits(builder, bits);
    Architecture.addProcessor(builder, processorOffset);
    Architecture.addEndian(builder, endian);
    return Architecture.endArchitecture(builder);
  }

  public static void startArchitecture(FlatBufferBuilder builder) { builder.startTable(5); }
  public static void addProcessor(FlatBufferBuilder builder, int processorOffset) { builder.addOffset(0, processorOffset, 0); }
  public static void addEndian(FlatBufferBuilder builder, boolean endian) { builder.addBoolean(1, endian, false); }
  public static void addBits(FlatBufferBuilder builder, long bits) { builder.addInt(2, (int)bits, (int)0L); }
  public static void addVariant(FlatBufferBuilder builder, int variantOffset) { builder.addOffset(3, variantOffset, 0); }
  public static void addAuxiliary(FlatBufferBuilder builder, int auxiliaryOffset) { builder.addOffset(4, auxiliaryOffset, 0); }
  public static int createAuxiliaryVector(FlatBufferBuilder builder, byte[] data) { return builder.createByteVector(data); }
  public static int createAuxiliaryVector(FlatBufferBuilder builder, ByteBuffer data) { return builder.createByteVector(data); }
  public static void startAuxiliaryVector(FlatBufferBuilder builder, int numElems) { builder.startVector(1, numElems, 1); }
  public static int endArchitecture(FlatBufferBuilder builder) {
    int o = builder.endTable();
    return o;
  }

  public static final class Vector extends BaseVector {
    public Vector __assign(int _vector, int _element_size, ByteBuffer _bb) { __reset(_vector, _element_size, _bb); return this; }

    public Architecture get(int j) { return get(new Architecture(), j); }
    public Architecture get(Architecture obj, int j) {  return obj.__assign(__indirect(__element(j), bb), bb); }
  }
}

