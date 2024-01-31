package org.pcap4j.packet;

import static org.pcap4j.packet.namednumber.Dot11InformationElementId.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

/**
 * 802.11 Deauthentication
 */
public final class Dot11DeAuthPacket extends Dot11ManagementPacket {

  /** */
  private static final long serialVersionUID = -230535575919172787L;

  private final Dot11DeAuthHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11DeAuthPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11DeAuthPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    Dot11DeAuthHeader h = new Dot11DeAuthHeader(rawData, offset, length);
    return new Dot11DeAuthPacket(rawData, offset, length, h);
  }

  private Dot11DeAuthPacket(
      byte[] rawData, int offset, int length, Dot11DeAuthHeader h) {
    super(rawData, offset, length, h.length());
    this.header = h;
  }

  private static Dot11DeAuthPacket newPacket(Builder builder) {
    Dot11DeAuthHeader h = new Dot11DeAuthHeader(builder);
    return new Dot11DeAuthPacket(builder, h);
  }

  private Dot11DeAuthPacket(Builder builder, Dot11DeAuthHeader h) {
    super(builder, h);
    this.header = h;
  }

  @Override
  public Dot11DeAuthHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11ManagementPacket.Builder {

    private Short reasonCode;
    private List<Dot11VendorSpecificElement> vendorSpecificElements;

    /** */
    public Builder() {}

    private Builder(Dot11DeAuthPacket packet) {
      super(packet);
      this.reasonCode = packet.header.reasonCode;
      this.vendorSpecificElements = packet.header.vendorSpecificElements;
    }

    /**
     * @param short reasonCode
     * @return this Builder object for method chaining.
     */
    public Builder reasonCode(short reasonCode) {
      this.reasonCode = reasonCode;
      return this;
    }

    /**
     * @param vendorSpecificElements vendorSpecificElements
     * @return this Builder object for method chaining.
     */
    public Builder vendorSpecificElements(List<Dot11VendorSpecificElement> vendorSpecificElements) {
      this.vendorSpecificElements = vendorSpecificElements;
      return this;
    }

    @Override
    public Builder frameControl(Dot11FrameControl frameControl) {
      super.frameControl(frameControl);
      return this;
    }

    @Override
    public Builder duration(short duration) {
      super.duration(duration);
      return this;
    }

    @Override
    public Builder address1(MacAddress address1) {
      super.address1(address1);
      return this;
    }

    @Override
    public Builder address2(MacAddress address2) {
      super.address2(address2);
      return this;
    }

    @Override
    public Builder address3(MacAddress address3) {
      super.address3(address3);
      return this;
    }

    @Override
    public Builder sequenceControl(Dot11SequenceControl sequenceControl) {
      super.sequenceControl(sequenceControl);
      return this;
    }

    @Override
    public Builder htControl(Dot11HtControl htControl) {
      super.htControl(htControl);
      return this;
    }

    @Override
    public Builder fcs(Integer fcs) {
      super.fcs(fcs);
      return this;
    }

    @Override
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      super.correctChecksumAtBuild(correctChecksumAtBuild);
      return this;
    }

    @Override
    public Dot11DeAuthPacket build() {
      checkForNull();
      return newPacket(this);
    }
  }

  /**
   * Header of 802.11 Deauthentication
   *
   * <pre style="white-space: pre;">
   *  0                             15
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         Frame Control         |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         Duration              |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address1             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address2             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address3             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |       Sequence Control        |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         HT Control            |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Frame Body           |
   * |                               |
   * </pre>
   *
   * <table>
   *   <caption>Frame Body</caption>
   *   <tr>
   *     <td>1</td>
   *     <td>Reason Code</td>
   *     <td>Check 802.11 Standard Deauthentication Codes.</td>
   *   </tr>
   *   <tr>
   *     <td>Last</td>
   *     <td>Vendor Specific</td>
   *     <td>
   *       One or more vendor-specific elements are optionally present. These elements follow all
   *       other elements.
   *     </td>
   *   </tr>
   * </table>
   *
   */
  public static final class Dot11DeAuthHeader extends Dot11ManagementHeader {

    /** */
    private static final long serialVersionUID = -2203820242563461514L;

    private final Short reasonCode;
    private final List<Dot11VendorSpecificElement> vendorSpecificElements;

    private Dot11DeAuthHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      super(rawData, offset, length);
      int mgmtHeaderLen = super.calcLength();
      offset += mgmtHeaderLen;
      length -= mgmtHeaderLen;

      if (length > 0) {
        reasonCode = (short) (((rawData[offset] & 0xFF) | (rawData[offset+1] & 0xFF) >> 8));
        offset += 2;
        length -= 2;
      } else {
        this.reasonCode = null;
      }

      this.vendorSpecificElements = new ArrayList<Dot11VendorSpecificElement>();
      while (length > 0 && rawData[offset] == VENDOR_SPECIFIC.value().byteValue()) {
        Dot11VendorSpecificElement elem =
            Dot11VendorSpecificElement.newInstance(rawData, offset, length);
        vendorSpecificElements.add(elem);
        int elemLen = elem.length();
        offset += elemLen;
        length -= elemLen;
      }
    }

    private Dot11DeAuthHeader(Builder builder) {
      super(builder);
      this.reasonCode = builder.reasonCode;
      if (builder.vendorSpecificElements == null) {
        this.vendorSpecificElements = Collections.emptyList();
      } else {
        this.vendorSpecificElements =
            new ArrayList<Dot11VendorSpecificElement>(builder.vendorSpecificElements);
      }
    }

    /** @return vendorSpecificElements */
    public List<Dot11VendorSpecificElement> getVendorSpecificElements() {
      return new ArrayList<Dot11VendorSpecificElement>(vendorSpecificElements);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = super.getRawFields();

      if (reasonCode != null) {
        byte[] rawData = new byte[4];
        rawData[0] = (byte) 0;
        rawData[1] = (byte) 2;
        short x = (short) reasonCode;
        rawData[2] = (byte)(x & 0xFF);
        rawData[3] = (byte)((x >> 8) & 0xFF);
        rawFields.add(rawData);
      }
      for (Dot11VendorSpecificElement elem : vendorSpecificElements) {
        rawFields.add(elem.getRawData());
      }

      return rawFields;
    }

    @Override
    public int calcLength() {
      int len = super.calcLength();

      if (reasonCode != null) {
        len += 2;
      }
      for (Dot11VendorSpecificElement elem : vendorSpecificElements) {
        len += elem.length();
      }

      return len;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append(super.buildString());
      sb.append("  Tags:").append(ls);
      if (reasonCode != null) {
        sb.append("    ").append(reasonCode.toString()).append(ls);
      }
      for (Dot11VendorSpecificElement elem : vendorSpecificElements) {
        sb.append(elem.toString("    "));
      }

      return sb.toString();
    }

    @Override
    protected String getHeaderName() {
      return "802.11 Deauthentication header";
    }

    @Override
    protected int calcHashCode() {
      final int prime = 31;
      int result = super.calcHashCode();
      result = prime * result + ((reasonCode == null) ? 0 : reasonCode.hashCode());
      result = prime * result + vendorSpecificElements.hashCode();
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (!super.equals(obj)) return false;
      Dot11DeAuthHeader other = (Dot11DeAuthHeader) obj;
      if (reasonCode == null) {
        if (other.reasonCode != null) return false;
      } else if (!reasonCode.equals(other.reasonCode)) return false;
      if (!vendorSpecificElements.equals(other.vendorSpecificElements)) return false;
      return true;
    }
  }
}
