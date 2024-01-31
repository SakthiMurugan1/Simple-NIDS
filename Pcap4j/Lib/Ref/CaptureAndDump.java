import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Iterator;
import java.sql.Timestamp;
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

class Mappings {

  public String IP;
  public String MAC;
  public int counts;
  public Timestamp timestamp1;
  public Timestamp timestamp2;

  private static final Logger logger = LoggerFactory.getLogger(Mappings.class);

  public static int MAP_TOTAL_COUNT=0;
  public static int MAP_MAP_THRESH_COUNT=10;
  
  public void log(String IP, MacAddress MAC, Timestamp timestamp1) {
    try {
      this.IP = IP;
      this.MAC = MAC.toString();
      this.counts=1;
      this.timestamp1 = timestamp1;
      this.timestamp2 = timestamp1;
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}


public class CaptureAndDump {

  private static int CAP_COUNT = -1; // total packets to capture
  private static final Logger logger = LoggerFactory.getLogger(CaptureAndDump.class);

  private static final String READ_TIMEOUT_KEY = CaptureAndDump.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 50); // [ms]

  private static final String SNAPLEN_KEY = CaptureAndDump.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  //private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName(MACAndIp.getMAC());
  private static ArrayList<Mappings> MAPDB = new ArrayList<>();

  private void CaptureAndDump() {}

  private static void addToMapDB(String IP1, MacAddress MAC1, Timestamp timestamp) {
    logger.info("Depositing packet to data store");
    Mappings mapping1 = new Mappings();
    Iterator itr = MAPDB.iterator();
    if(!itr.hasNext()) {
      mapping1.log(IP1, MAC1, timestamp);
      MAPDB.add(mapping1);
      Mappings.MAP_TOTAL_COUNT+=1;
      return;
    }
    while(itr.hasNext()) {
      Mappings m = (Mappings) itr.next();
      if(m.IP.equals(IP1) && m.MAC.equals(MAC1.toString())) {
        m.counts+=1;
        m.timestamp2 = timestamp;
        Mappings.MAP_TOTAL_COUNT+=1;
        return;
      } else {
        continue;
      }
    }
    mapping1.log(IP1, MAC1, timestamp);
    MAPDB.add(mapping1);
    Mappings.MAP_TOTAL_COUNT+=1;
  }

  private static void findAnomalies(ArrayList<Mappings> mdb) {
    logger.info("Looking for anamalies");
    // First check if an attack actually increases the count within a short time by actually running an attack and viewing the mapstore
    // Iterate through all the entries and find the counts if more and timestamp difference is less then an attack is detected
    // Also Iterate through the entries and find if a pair info is changed from the previous ARPSCAN file
    // Also use the ARPSCAN file to send defensive arps
    // Finally connect with the IDS file and run a test
  }
  public static void main(String[] argv) throws PcapNativeException, NotOpenException {

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
    
    logger.info("Starting traffic capture");
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    String strSrcIpAddress = MACAndIp.getIPAddress(); // for InetAddress.getByName()

    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapDumper dumper = handle.dumpOpen("Out.pcap");
    logger.info("Dumping packets onto \"Out.pcap\"\n");
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

                addToMapDB(strSrcIp, resolvedAddr, handle.getTimestamp());
                if(Mappings.MAP_TOTAL_COUNT>=Mappings.MAP_MAP_THRESH_COUNT) {
                  Task2 newTask = new Task2();
                  pool2.execute(newTask);
                }

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
      Mappings.MAP_TOTAL_COUNT=0;
      findAnomalies(MAPDB);
      MAPDB.clear();
    }
  }
}
