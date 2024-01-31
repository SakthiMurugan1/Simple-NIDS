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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
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
    try {
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
    } catch(Exception E) {
      E.printStackTrace();  //print Exception StackTrace
      return null;
    } 
  }
  public static String getIPAddress(){
    try{
      InetAddress inetaddress=InetAddress.getLocalHost();  //Get LocalHost refrence
      String ip = inetaddress.getHostAddress();  // Get Host IP Address
      return ip;   // return IP Address
    } catch(Exception E){
      E.printStackTrace();  //print Exception StackTrace
      return null;
    }   
  }
}

//@SuppressWarnings("javadoc")
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
    PcapDumper dumper = sendHandle.dumpOpen("ArpScan.pcap");
    logger.info("Dumping packets onto \"ArpScan.pcap\"\n");
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
        dumper.dump(p);
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

class Mappings {
  public String IP;
  public String MAC;
  public int counts;

  private static final Logger logger = LoggerFactory.getLogger(Mappings.class);
  
  public void log(String IP, MacAddress MAC) {
    try {
      this.IP = IP;
      this.MAC = MAC.toString();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

//@SuppressWarnings("unchecked")
class CaptureAndAnalyze {

  private static String ARPLIST = "arpList.txt"; //List containing arp data
  private static int CAP_COUNT = -1; // total packets to capture
  private static final Logger logger = LoggerFactory.getLogger(CaptureAndAnalyze.class);
  private static PcapNetworkInterface NIF;

  private static final String READ_TIMEOUT_KEY = CaptureAndAnalyze.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 50); // [ms]

  private static final String SNAPLEN_KEY = CaptureAndAnalyze.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  //private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName(MACAndIp.getMAC());
  private static List<Mappings> MAPDB = new CopyOnWriteArrayList<>();

  private void CaptureAndAnalyze() {}

  private static void addToMapDB(String IP1, MacAddress MAC1) {
    logger.info("Depositing packet to data store");
    Mappings mapping1 = new Mappings();
    Iterator itr = MAPDB.iterator();
    if(!itr.hasNext()) {
      mapping1.log(IP1, MAC1);
      MAPDB.add(mapping1);
      return;
    }
    while(itr.hasNext()) {
      Mappings m = (Mappings) itr.next();
      if(m.IP.equals(IP1) && m.MAC.equals(MAC1.toString())) {
        m.counts+=1;
        return;
      } else {
        continue;
      }
    }
    mapping1.log(IP1, MAC1);
    MAPDB.add(mapping1);
  }

  private static void analyze() {    
    logger.info("Analysis Started");
    File file = new File(ARPLIST);
    Mappings mappings1 = new Mappings();

    while(true) { 
      Iterator itr = MAPDB.iterator();
      if(itr.hasNext()) {
        mappings1 = (Mappings) itr.next();
        logger.info("Analyzing packet");
        try {
          Scanner scanner = new Scanner(file);
          while (scanner.hasNextLine()) {
            String lineFromFile = scanner.nextLine();
            String[] IpMac = lineFromFile.split(" ");
            if (IpMac[0].equals(mappings1.IP) && IpMac[1].equals(mappings1.MAC)) {
              logger.info("Entry valid, moving on");
              break;
            } else if (IpMac[0].equals(mappings1.IP) && !IpMac[1].equals(mappings1.MAC)) {
              logger.warn("Attacker detected, sending defensive ARPs");
              //send defensive arps
              sendArps(IpMac[0], IpMac[1], mappings1.IP);
              break;
            } else if (!scanner.hasNextLine()) {
              try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(ARPLIST, true), "UTF-8"))) {
                writer.write(mappings1.IP + " " + mappings1.MAC + "\n");
                logger.info("New ARP reply found");
              } catch (IOException e) {
                e.printStackTrace();
              }
            }
          }
        } catch (FileNotFoundException e) {
          e.printStackTrace();
        }
      } else {
        try {
          Thread.sleep(100);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
      MAPDB.remove(mappings1);
      //Check for the mismatch with the file if found then send defensive arps and remove the entry from the MAPDB
      //If no match at all add it to the file
      //If matched move on
    }
  }

  public static void sendArps(String originalIP, String originalMAC, String strDstIpAddress)
  {
    PcapNetworkInterface nif = NIF;
    try {
      PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
      ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
      for (int i = 0; i < 2; i++) {
        try {
          arpBuilder
              .hardwareType(ArpHardwareType.ETHERNET)
              .protocolType(EtherType.IPV4)
              .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
              .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
              .operation(ArpOperation.REPLY)
              .srcHardwareAddr(MacAddress.getByName(originalMAC))
              .srcProtocolAddr(InetAddress.getByName(originalIP))
              .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
              .dstProtocolAddr(InetAddress.getByName(strDstIpAddress));
        } catch (UnknownHostException e) {
          throw new IllegalArgumentException(e);
        }
            
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
            .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
            .srcAddr(MacAddress.getByName(originalMAC))
            .type(EtherType.ARP)
            .payloadBuilder(arpBuilder)
            .paddingAtBuild(true);
        
        //logger.info("Building Packet " + (i+1) + ":");
        Packet p = etherBuilder.build();
        //System.out.println(p);
        logger.info("Defensive ARP(s) sent");
        sendHandle.sendPacket(p);
        try {
          Thread.sleep(200);
        } catch (InterruptedException e) {
          break;
        }
      }
    } catch (PcapNativeException e) {
      e.printStackTrace();
    } catch (NotOpenException e) {
      e.printStackTrace();
    }
  }
  public static void trafficScan(PcapNetworkInterface nifChosen) throws PcapNativeException, NotOpenException {

    PcapNetworkInterface nif = nifChosen;
    NIF = nifChosen;
    
    System.out.print("\n");
    System.out.println("Using interface: " + nif.getName() + "(" + nif.getDescription() + ")");
    logger.info("Starting traffic capture");
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    String strSrcIpAddress = MACAndIp.getIPAddress(); // for InetAddress.getByName()

    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapDumper dumper = handle.dumpOpen("NetworkData.pcap");
    logger.info("Dumping packets onto \"NetworkData.pcap\"\n");
    ExecutorService pool = Executors.newSingleThreadExecutor();
    ExecutorService pool2 = Executors.newSingleThreadExecutor();

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
                logger.info(strSrcIp + " was resolved to " + resolvedAddr);

                addToMapDB(strSrcIp, resolvedAddr);

                // Dump packets to file
                try {
                  dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                  e.printStackTrace();
                }
              } else {
                //logger.info("Not an ARP REPLY packet");
              }
              //System.out.println(handle.getTimestamp());
              //System.out.println(packet);
            }
        };

      Task t = new Task(handle, listener);
      pool.execute(t);
      Task2 newTask = new Task2();
      pool2.execute(newTask);

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
      if (pool2 != null && !pool2.isShutdown()) {
        pool2.shutdown();
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
        handle.loop(CAP_COUNT, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
        e.printStackTrace();
      } catch (NotOpenException e) {
        e.printStackTrace();
      }
    }
  }
  private static class Task2 implements Runnable {
    public void run() {
      analyze();
    }
  }
}

public class IDS {
  public static void main(String[] args) {

    System.out.println("\nAlbatross - Network Intrusion Detection System\n");
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

    CaptureAndAnalyze Cap = new CaptureAndAnalyze();
    try {
      Cap.trafficScan(nif);
    } catch (PcapNativeException e) {
      e.printStackTrace();
    } catch (NotOpenException e) {
      e.printStackTrace();
    }
  }
}
