package org.jnetpcap.examples;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class s {
	static int nr=0;
	
	//////////////la liste de tt le materiel:::::::::::::::::::
	static public void ListeMat(){
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		 String tabB[] = new String[20];
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("impossible de lister, erreur : %s",
					errbuf.toString());
			return;
		}else{
			
		JOptionPane.showMessageDialog(null, " dispositifs trouvé...ok! : ");

int i = 0;
for (PcapIf device : alldevs) {
	String description = (device.getDescription() != null) ? device
			.getDescription() : "aucune description trouvée!";
	
			
			System.out.println(""+i++ +"-" +device.getName()+" "+	description+"\n") ;
			System.out.println(""+i+" "+	description+ " "+"\n") ;
		
}
 }
	  }
	  
	
	
	
	
	
	
	
	
	
	
	
	////////////////////////////////:capture::::::::::::::::::
	public static void sniff(){
		
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // 
		StringBuilder errbuf = new StringBuilder(); // pour erreur
		int r = Pcap.findAllDevs(alldevs, errbuf);
		
		LocalDate ld = LocalDate.now();
		LocalTime lt = LocalTime.now();
		System.out.println("\n ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Capture : ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Capture : /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// \n");
		System.out.println("date : "+ld+"\n" );
		System.out.println("heure : "+lt+"\n" );
		
		//****************ouvrir le divice selectioné***************//
		 
		PcapIf device = alldevs.get(0);
		
		int snaplen = 64 * 1024; // tt les packet
		int flags = Pcap.MODE_PROMISCUOUS; // tt
		int timeout = 3 * 1000; // 
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		if (pcap == null) {
			System.out.println("\n Erreur lors de louverture: "
					+ errbuf.toString()+"\n");
			JOptionPane.showMessageDialog(null, "erreur lors de l'ouverture ");
			
			
			return;
		}
		
		//***********creation du packet handler qui va recevoire les paquet depuis LibCap loop********//
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			
			public void nextPacket(PcapPacket packet, String user) {
				
				Ip4 ip2 = new Ip4();
				Ip6 ip6 = new Ip6();
                Ethernet eth=new Ethernet();
                String sIP2;
                String dIP2;
                String sIP6;
                String dIP6;
                Arp arp=new Arp();
                
                int totalLength=0;
                int totalLengthIp6=0;
                if (packet.hasHeader(arp)) {
                	System.out.println("Hardware type" + arp.hardwareType());
                	System.out.println("Protocol type" + arp.protocolType());
                	System.out.println("Packet:" + arp.getPacket());
                	System.out.println();
                	}
                
                
                if (packet.hasHeader(ip2) == false){
                	System.out.println("erreur header");
                	JOptionPane.showMessageDialog(null, "erreur header ");
                    return;
                }else{
                 totalLength = totalLength+ ip2.getPayloadLength();
                 sIP2 = org.jnetpcap.packet.format.FormatUtils.ip(ip2.source());
                 dIP2 = org.jnetpcap.packet.format.FormatUtils.ip(ip2.destination());
                }
                 if (packet.hasHeader(ip2) == false){
                 	System.out.println("erreur header");
                 	JOptionPane.showMessageDialog(null, "erreur header ");
                     return;
                 }else{
                 totalLengthIp6 = totalLengthIp6+ ip6.getPayloadLength();
                 sIP6 = org.jnetpcap.packet.format.FormatUtils.ip(ip2.source());
                 dIP6 = org.jnetpcap.packet.format.FormatUtils.ip(ip2.destination());
                 System.out.println();}
                
           
				
                 final JHeaderPool headers = new JHeaderPool();  
                 final int count = packet.getHeaderCount();  
                 for (int i = 0; i < count; i++) {  
                   final int id = packet.getHeaderIdByIndex(i); // Numerical ID of the header  
                   final JHeader header = headers.getHeader(id);  
                   final String name = header.getName();  
                   final String nicname = header.getNicname();  
                   final String description = header.getDescription();  
                   final JField[] fields = header.getFields();  
                   final AnnotatedHeader annotatedHeader = header.getAnnotatedHeader(); // Annotatio
                  
                 }
                 //////choix ip  tcp  udp  eth  data//////
                 int id = packet.getHeaderIdByIndex(1);
                 
                 JHeaderPool headerPool = new JHeaderPool();
                 int count2 = packet.getHeaderCount();
                 int idProtocol = 0;

                 

                 
                 if(id >= idProtocol){
                 idProtocol = id;
                 }

                
                 JHeader header = headerPool.getHeader(id);
                 
                 
                 Http http = new Http();
                
                 System.out.printf("http header::%s%n", http);
                

                

                         
                     
nr++;
                 
    			
    			LocalDate ld2 = LocalDate.now();
    			LocalTime lt2 = LocalTime.now();
    			
    			System.out.println("\n"+ "DATE "+ld2+""+ "HEURE "+lt2+"\""+ " SOURCE "+sIP2+"\""+ "  DESTINATION "+dIP2+"\"  ID "+id+"\"  NICKNAME  "+header.getNicname()+"\"  NOM "+""+header.getName()+"\"  "+ " DESCRIPTION "+header.getDescription()+"\"   FIELD "+header.getFields()+"\"     "+ " ANNOTATION "+header.getAnnotatedHeader()+"  "
    		+ ""+ " caplen=" + packet.getCaptureHeader().caplen()+" TAILLE "+packet.size()+"     "+arp.getPacket()+"\n");
               
    			
                
            }  
        };  
        
        ///**********nb de paquet a scapturer**********//

        
		
		pcap.loop(10, jpacketHandler, "jNetPcap");
		pcap.close();
		LocalDate ld3 = LocalDate.now();
		LocalTime lt3 = LocalTime.now();
		
		System.out.println("\n ///////////////////////FIN!! ///////////////////////  "+"\n");
		System.out.println("date : "+ld3+"\n" );
		System.out.println("heure : "+lt3+"\n" );
		System.out.println("nombre de packet cherché : "+10+"\n" );
		System.out.println("nombre de packet capturé :"+nr+"\n");
		
			
			JOptionPane.showMessageDialog(null, "Fin de la Capture ");
			
	}
	
	
	
	
	public static void decode(){
		final int INTERFACE = 2;
		List alldevs = new ArrayList(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		// Get a list of devices on this system
		int r = Pcap.findAllDevs(alldevs, errbuf);

		if(alldevs.isEmpty())
		System.out.println(r);

		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
		System.err.printf("Can't read list of devices, error is %s", errbuf.toString());

		return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		List<PcapIf> alldevs2 = new ArrayList<PcapIf>();

		for (PcapIf device : alldevs2) {
		System.out.printf("#%d: %s [%s]\n", i++, device.getName(), device.getDescription());
		}
		PcapIf device = alldevs2.get(INTERFACE); // We know we have atleast 1 device
		System.out.printf("\nChoosing '%s' '%s' on your behalf:\n", device.getDescription(), device.getName());

		// Open up the selected driver
		int snaplen = 64 * 1024; // Capture all packets, no truncation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 1 * 1000; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
		System.err.printf("Error while opening device for capture: "
		+ errbuf.toString());
		return;
		}
		JPacketHandler handler = new JPacketHandler() {
		
			

			@Override
			public void nextPacket(JPacket packet, Object user) {
				// TODO Auto-generated method stub
				final JCaptureHeader header = packet.getCaptureHeader();
				System.out.println(packet.toString());
					System.out.printf("\n");
					System.out.println ("--------------------------------------------");
					System.out.println(packet.toHexdump());
					System.out.println(packet);
				System.out.println("*******************************************************");

				
			}

		
		};

		//Enter the loop and tell it to capture

		pcap.loop(4, handler,"JnetPcap"); //loop 4 packets.you can change the number
		pcap.close();
		}
	
		
	 
	      
	 

	public static void main(String[] args) {
		// TODO Auto-generated method stub
ListeMat();
sniff();

	}

}
