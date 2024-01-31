//Dont forget to remove the live host identifier and the SCAN_PCOUNT loops and the SCAN_PCOUNT if check, It's just for the testings

import java.io.IOException;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.Writer;
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
import org.pcap4j.core.PcapDumper;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MACAndIp {
  public static String getMAC(){
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

  public static String getIPAddress(){
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
}

@SuppressWarnings("javadoc")
class ARPScan{

  private static String ARPLIST = "arpList.txt"; //List containing arp data
  private static int SCAN_PCOUNT = 1; // total packets to send and wait to receive
  private static int SCAN_TCOUNT = 10; // total hosts to scan on the network
  private static final Logger logger = LoggerFactory.getLogger(ARPScan.class);

  private static final String READ_TIMEOUT_KEY = ARPScan.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = ARPScan.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName(MACAndIp.getMAC());

  private void ARPScan() {}

  private static void writeToFile (String str) {
    File file = new File(ARPLIST);
    try {
      if (file.exists()) {
        Scanner scanner = new Scanner(file);
        while (scanner.hasNextLine()) {
          String lineFromFile = scanner.nextLine();
          if(lineFromFile.contains(str)) {
            return;
          }
        }
      }
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(ARPLIST, true), "UTF-8"))) {
      writer.write(str);
      writer.write("\n");
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
  
  public static void newScan(PcapNetworkInterface nifChosen) throws PcapNativeException, NotOpenException {
    
    PcapNetworkInterface nif = nifChosen;
    System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

    String strSrcIpAddress = MACAndIp.getIPAddress(); // for InetAddress.getByName()
    String strDstIpRange = ""; // for InetAddress.getByName()
    String[] strDstIpAddress = null;

    System.out.print("\n");
    logger.info("Starting new ARP Scan");
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);

    Scanner scanner = new Scanner(System.in);
    while(true) {
      try {
        System.out.print("\nEnter the network range to scan > ");
        strDstIpRange = scanner.nextLine();
        SubnetUtils ipRange = new SubnetUtils(strDstIpRange);
        strDstIpAddress = ipRange.getInfo().getAllAddresses();
        //SCAN_TCOUNT = strDstIpAddress.length;
        break;
      } catch (IllegalArgumentException E) {
        System.out.println("Invalid IP Range.");
        continue;
      }
    }

    logger.info("Checking for live hosts");
    SCAN_PCOUNT = 0;
    try {
      for(int j=0; j<SCAN_TCOUNT; j++) {
        if (InetAddress.getByName(strDstIpAddress[j]).isReachable(100)) {
          logger.info(" Reachable Host : " + strDstIpAddress[j]);
          strDstIpAddress[SCAN_PCOUNT]=strDstIpAddress[j];
          SCAN_PCOUNT += 1;
        }
      }
    } catch (UnknownHostException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    System.out.print("\n");

    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();

    if (SCAN_PCOUNT<=0) {
      logger.info("No live hosts found");
      return;
    }

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
              //System.out.println(packet);
              if (resolvedAddr!=null) {
                logger.info(strSrcIp + " was resolved to " + resolvedAddr + "\n");
                writeToFile(strSrcIp + " " + resolvedAddr.toString());
              }
            }
          };

      Task t = new Task(handle, listener);
      pool.execute(t);

      ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
      for (int i = 0; i < SCAN_PCOUNT; i++) {
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

	//logger.info("Building Packet " + (i+1) + ":");
        Packet p = etherBuilder.build();
        //System.out.println(p);
	//logger.info("Sending ARP Packet");
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
        handle.loop(SCAN_PCOUNT, listener);
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

class CaptureAndDump {

  private static int COUNT = 1; // total packets to capture
  private static final Logger logger = LoggerFactory.getLogger(CaptureAndDump.class);

  private static final String READ_TIMEOUT_KEY = CaptureAndDump.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 50); // [ms]

  private static final String SNAPLEN_KEY = CaptureAndDump.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName(MACAndIp.getMAC());

  private void CaptureAndDump() {}
  
  public void trafficScan(PcapNetworkInterface device) throws PcapNativeException, NotOpenException {

    PcapNetworkInterface nif = device;
    
    System.out.println("\nStarting traffic capture...");
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    String strSrcIpAddress = MACAndIp.getIPAddress(); // for InetAddress.getByName()

    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapDumper dumper = handle.dumpOpen("Out.pcap");
    logger.info("Dumping packets onto \"Out.pcap\"\n");
    ExecutorService pool = Executors.newSingleThreadExecutor();

    try {
      handle.setFilter("arp", BpfCompileMode.OPTIMIZE);

      PacketListener listener =
          new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
              String strSrcIp = "";
              MacAddress resolvedAddr = null;
              ArpPacket arp = packet.get(ArpPacket.class);
              if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                resolvedAddr = arp.getHeader().getSrcHardwareAddr();
                strSrcIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
                logger.info(strSrcIp + " was resolved to " + resolvedAddr + "\n");
              } else {}

              //System.out.println(handle.getTimestamp());
              //System.out.println(packet);

              // Dump packets to file
              try {
                dumper.dump(packet, handle.getTimestamp());
              } catch (NotOpenException e) {
                e.printStackTrace();
              }
            }
        };

      Task t = new Task(handle, listener);
      pool.execute(t);

      try {
        Thread.sleep(200);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }

    } finally {
      if (handle != null && handle.isOpen()) {
        handle.close();
      }
      if (dumper != null && dumper.isOpen()) {
        dumper.close();
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

public class IDS {
  public static void main(String[] args) {
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

    ARPScan Scanner = new ARPScan();
    try {
      Scanner.newScan(nif);
    } catch (PcapNativeException e) {
      e.printStackTrace();
    } catch (NotOpenException e) {
      e.printStackTrace();
    }

    CaptureAndDump Cap = new CaptureAndDump();
    try {
      Cap.trafficScan(nif);
    } catch (PcapNativeException e) {
      e.printStackTrace();
    } catch (NotOpenException e) {
      e.printStackTrace();
    }
  }
}
