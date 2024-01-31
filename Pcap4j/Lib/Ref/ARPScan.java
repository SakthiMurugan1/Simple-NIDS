import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Scanner;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import org.apache.commons.net.util.SubnetUtils;

@SuppressWarnings("javadoc")
public class ARPScan{

  private static int COUNT = 1;

  private static final String READ_TIMEOUT_KEY = ARPScan.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = ARPScan.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName(getMAC());

  private static String getMAC(){
       try{
          InetAddress inetaddress=InetAddress.getLocalHost(); //Get LocalHost refrence
          
          //get Network interface Refrence by InetAddress Refrence
          NetworkInterface network = NetworkInterface.getByInetAddress(inetaddress); 
          byte[] macArray = network.getHardwareAddress();  //get Harware address Array

          StringBuilder str = new StringBuilder();
          for (int i = 0; i < macArray.length; i++) {
                  str.append(String.format("%02X%s", macArray[i], (i < macArray.length - 1) ? ":" : ""));
          }
          String macAddress=str.toString();
          return macAddress;
      }
      catch(Exception E){
          E.printStackTrace();  //print Exception StackTrace
          return null;
      } 
  }
  private static String getIPAddress(){
       try{
          InetAddress inetaddress=InetAddress.getLocalHost();  //Get LocalHost refrence
          String ip = inetaddress.getHostAddress();  // Get Host IP Address
          return ip;   // return IP Address
      }
      catch(Exception E){
          E.printStackTrace();  //print Exception StackTrace
          return null;
      }
       
  }
  private ARPScan() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String strSrcIpAddress = getIPAddress(); // for InetAddress.getByName()
    String strDstIpRange = ""; // for InetAddress.getByName()
    String[] strDstIpAddress = null;

    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println("\n");

    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    if (nif == null) {
      return;
    }

    System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

    Scanner scanner = new Scanner(System.in);
    while(true) {
      try {
        System.out.print("\nEnter the network range to scan > ");
        strDstIpRange = scanner.nextLine();
        SubnetUtils ipRange = new SubnetUtils(strDstIpRange);
        strDstIpAddress = ipRange.getInfo().getAllAddresses();
        COUNT = strDstIpAddress.length;
        break;
      } catch (IllegalArgumentException E) {
        System.out.println("Invalid IP Range.");
        continue;
      }
    }

    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();

    try {
      handle.setFilter(
          "arp and dst host "
              + strSrcIpAddress
              + " and ether dst "
              + Pcaps.toBpfString(SRC_MAC_ADDR),
          BpfCompileMode.OPTIMIZE);

      PacketListener listener =
          new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
              String strSrcIp = "";
              MacAddress resolvedAddr = null;
              if (packet.contains(ArpPacket.class)) {
                ArpPacket arp = packet.get(ArpPacket.class);
                if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                  resolvedAddr = arp.getHeader().getSrcHardwareAddr();
                  strSrcIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
                }
              }
              //System.out.println("\nRecieving Data:");
              //System.out.println(packet);
              System.out.println(strSrcIp + " was resolved to " + resolvedAddr + "\n");
            }
          };

      Task t = new Task(handle, listener);
      pool.execute(t);

      ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
      for (int i = 0; i < COUNT; i++) {
        try {
          arpBuilder
              .hardwareType(ArpHardwareType.ETHERNET)
              .protocolType(EtherType.IPV4)
              .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
              .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
              .operation(ArpOperation.REQUEST)
              .srcHardwareAddr(SRC_MAC_ADDR)
              .srcProtocolAddr(InetAddress.getByName(strSrcIpAddress))
              .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
              .dstProtocolAddr(InetAddress.getByName(strDstIpAddress[i]));
        } catch (UnknownHostException e) {
          throw new IllegalArgumentException(e);
        }

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
            .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
            .srcAddr(SRC_MAC_ADDR)
            .type(EtherType.ARP)
            .payloadBuilder(arpBuilder)
            .paddingAtBuild(true);

	//System.out.println("\nBuilding Packet " + (i+1) + ":");
        Packet p = etherBuilder.build();
        //System.out.println(p);
	//System.out.println("Sending ARP Packet...");
        sendHandle.sendPacket(p);
        try {
          Thread.sleep(200);
        } catch (InterruptedException e) {
          break;
        }
      }
    } finally {
      if (handle != null && handle.isOpen()) {
        handle.close();
      }
      if (sendHandle != null && sendHandle.isOpen()) {
        sendHandle.close();
      }
      if (pool != null && !pool.isShutdown()) {
        pool.shutdown();
      }
    }
  }

  private static class Task implements Runnable {

    private PcapHandle handle;
    private PacketListener listener;

    public Task(PcapHandle handle, PacketListener listener) {
      this.handle = handle;
      this.listener = listener;
    }

    @Override
    public void run() {
      try {
        handle.loop(COUNT, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
        e.printStackTrace();
      } catch (NotOpenException e) {
        e.printStackTrace();
      }
    }
  }
}
