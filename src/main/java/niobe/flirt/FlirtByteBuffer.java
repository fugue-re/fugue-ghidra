package niobe.flirt;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

public class FlirtByteBuffer {
  private ByteBuffer bytesView;

  public FlirtByteBuffer(byte[] buffer) {
    this.bytesView = ByteBuffer.wrap(buffer);
  }

  public byte read8() {
    return bytesView.get();
  }

  public short read16be() {
    int r = (read8() & 0xff) << 8;
    r |= (read8() & 0xff);
    return (short)(r & 0xffff);
      //return bytesView.order(ByteOrder.BIG_ENDIAN).getShort();
  }

  public short read16le() {
    return bytesView.order(ByteOrder.LITTLE_ENDIAN).getShort();
  }

  public int read24be() {
    int upper = (read8() & 0xff) << 16;
    return upper | (read16be() & 0xffff);
  }

  public int read32be() {
    int r = (read16be() & 0xffff) << 16;
    r |= read16be();
    return (int)(r & 0xffffffff);
  }

  public int read32le() {
    return bytesView.order(ByteOrder.LITTLE_ENDIAN).getInt();
  }

  public long read64be() {
    return bytesView.order(ByteOrder.BIG_ENDIAN).getLong();
  }

  public long read64le() {
    return bytesView.order(ByteOrder.LITTLE_ENDIAN).getLong();
  }

  public byte[] read(int n) throws IOException {
    var buf = new byte[n];
    bytesView.get(buf);
    return buf;
  }

  public short readMaxTwoBytes() {
    short b = (short)(read8() & 0xff);// & 0xff;
    if ((b & 0x80) == 0x80) {
      return (short)(((b & 0x7f) << 8) | (read8() & 0xff));
    } else {
      return b;
    }
  }

  public int readMultipleBytes() {
    int b = read8();
    if ((b & 0x80) != 0x80) {
      return b;
    } else if ((b & 0xc0) != 0xc0) {
      return ((b & 0x7f) << 8) | (read8() & 0xff);
    } else if ((b & 0xe0) != 0xe0) {
      return ((b & 0x3f) << 24) | (read24be() & 0xffffff);
    } else {
      return read32be();
    }
  }

  public long readNodeVariantMask(int length) throws IOException {
    if (length < 0x10) {
      return (long)readMaxTwoBytes() & 0xffffL;
    } else if (length <= 0x20) {
      return (long)readMultipleBytes() & 0xffffffffL;
    } else if (length <= 0x40) {
      long upper = (long)readMultipleBytes() << 32L;
      return upper | ((long)readMultipleBytes() & 0xffffffffL);
    } else {
      throw new IOException("invalid node variant mask length: " + length);
    }
  }

  public void readNodeBytes(int length, long variantMaskValue, ArrayList<Byte> pattern, ArrayList<Boolean> variantMask) {
    long maskBit = 1L << ((long)length - 1L);
    for (var i = 0; i < length; ++i) {
      var currMaskBool = (variantMaskValue & maskBit) != 0L;
      if (currMaskBool) {
        pattern.add(Byte.valueOf((byte)0));
      } else {
        pattern.add(Byte.valueOf(read8()));
      }
      variantMask.add(Boolean.valueOf(currMaskBool));
      maskBit >>= 1L;
    }
  }


  public FlirtByteBuffer deflateFrom() throws IOException {
      var outputStream = new ByteArrayOutputStream();
      var inflater = new Inflater(true);
      var infOutputStream = new InflaterOutputStream(outputStream, inflater);

      var tempBytes = new byte[1024];
      while (bytesView.hasRemaining()) {
        var amount = Math.min(bytesView.remaining(), tempBytes.length);
        bytesView.get(tempBytes, 0, amount);
        infOutputStream.write(tempBytes, 0, amount);
      }
      infOutputStream.write(new byte[]{0}); // nowrap
      infOutputStream.finish();

      return new FlirtByteBuffer(outputStream.toByteArray());
  }
}
