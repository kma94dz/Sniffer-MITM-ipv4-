package org.jnetpcap.examples;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.util.checksum.Checksum;

public class GetIPnMac {

private static ArrayList<String> ips = new ArrayList<String>();
private static ArrayList<String> macs = new ArrayList<String>();

public static void main(String[] args) throws UnknownHostException,
IOException {


}
public static final String BRODACAST_ADDRESS="FFFFFFFFFFFF";
public static final String DATA_TYPE="0806";
public static final String PADDING="000000000000000000000000000000000000";
public static final String ARP_HEADER_REQUEST ="0001 0800 06 04 0001";
public static final String ARP_HEADER_REPLY ="0001 0800 06 04 0002";
public static final String MAC_DESTINATION="000000000000";


public JPacket Generate_ArpRequest(String MAC_SOURCE,String IP_SOURCE,String IP_DESTINATION){
	
	String Frame_WithoutCRC32=BRODACAST_ADDRESS+MAC_SOURCE+DATA_TYPE+ARP_HEADER_REQUEST+MAC_SOURCE+IP_SOURCE+MAC_DESTINATION+IP_DESTINATION+PADDING;
	
	JPacket arpRequest =new JMemoryPacket(JProtocol.ETHERNET_ID,Frame_WithoutCRC32);
	
	return new JMemoryPacket(JProtocol.ETHERNET_ID,Frame_WithoutCRC32+Integer.toHexString(Checksum.crc32IEEE802(arpRequest,0, arpRequest.size())));//Complete Frame (Ready to sent)
}


public JPacket Generate_ArpReply(String MAC_SOURCE,String MAC_DESTINATION,String IP_SOURCE,String IP_DESTINATION){
	
	String Frame_WithoutCRC32=MAC_DESTINATION+MAC_SOURCE+DATA_TYPE+ARP_HEADER_REPLY+MAC_SOURCE+IP_SOURCE+MAC_DESTINATION+IP_DESTINATION+PADDING;
	
	JPacket arpRequest =new JMemoryPacket(JProtocol.ETHERNET_ID,Frame_WithoutCRC32);
	String CRC32=Integer.toHexString(Checksum.crc32IEEE802(arpRequest,0, arpRequest.size()));
	while(CRC32.length()<8){
		CRC32="0"+CRC32;
	}
	return new JMemoryPacket(JProtocol.ETHERNET_ID,Frame_WithoutCRC32+CRC32);
}



// get the mac address of an IP using the arp -a IP_ADDRESS command
public static String getMACWindows(String ip) {
String output = "";
try {
Runtime r = Runtime.getRuntime();
Process p = r.exec("arp -a " + ip);
BufferedInputStream in = new BufferedInputStream(p.getInputStream());

int temp = in.read();
while (temp != -1) {
output += (char) temp;
temp = in.read();
}

} catch (Exception e) {
e.printStackTrace();
}
return output;
}


}