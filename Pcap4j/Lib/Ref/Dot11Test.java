import org.pcap4j.packet.Dot11DeAuthPacket;
import org.pcap4j.packet.Dot11FrameControl;
import org.pcap4j.packet.namednumber.Dot11FrameType;
import org.pcap4j.packet.Dot11SequenceControl;
import org.pcap4j.util.MacAddress;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;
import java.io.IOException;

public class Dot11Test {

  public static void main(String[] argv) {

    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    Dot11FrameControl.Builder fcBldr = new Dot11FrameControl.Builder();
    fcBldr
	  .protocolVersion(Dot11FrameControl.ProtocolVersion.V0)
	  .type(Dot11FrameType.DEAUTHENTICATION)
	  .toDs(false)
	  .fromDs(true)
	  .moreFragments(false)
	  .retry(false)
	  .powerManagement(false)
	  .moreData(false)
	  .protectedFrame(false)
	  .order(false);
    Dot11FrameControl frmCtrl = fcBldr.build();
    System.out.print(frmCtrl);

    short dur = 48;
    MacAddress addr1 = MacAddress.getByName("44:1C:A8:A6:DC:B1");
    MacAddress addr2 = MacAddress.getByName("F0:1C:2D:A2:1C:00");
    MacAddress addr3 = MacAddress.getByName("F0:1C:2D:A2:1C:00");

    Dot11SequenceControl.Builder sqBldr = new Dot11SequenceControl.Builder();
    sqBldr
	 .fragmentNumber((byte) 0)
	 .sequenceNumber((short) 0);
    Dot11SequenceControl sqCtrl = sqBldr.build();
    System.out.print(sqCtrl);

    Dot11DeAuthPacket.Builder deauthBldr = new Dot11DeAuthPacket.Builder();
    deauthBldr
	  .reasonCode((short) 3)
	  .vendorSpecificElements(null)
	  .frameControl(frmCtrl)
	  .duration(dur)
	  .address1(addr1)
	  .address2(addr2)
	  .address3(addr3)
	  .sequenceControl(sqCtrl)
	  .htControl(null)
	  .fcs(null)
	  .correctChecksumAtBuild(true);
    Dot11DeAuthPacket p = deauthBldr.build();
    try {
      PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
      PcapDumper dumper = handle.dumpOpen("Out.pcap");
      dumper.dump(p);
    } catch (PcapNativeException e) {
      e.printStackTrace();
    } catch(NotOpenException e) {
      e.printStackTrace();
    }
  }
}