package NotreProjet;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Cmd {
	
	
	List <Machine_Connectée_IP_Mac> Liste_Des_Machines = new ArrayList<Machine_Connectée_IP_Mac>() ;

	///////////////////////////:executer la commande///////////////////////////////////////////////////////////////
public StringBuilder exec_Cmd(String Command) throws InterruptedException, IOException{
	Process p = Runtime.getRuntime().exec(Command);
	p.waitFor();
	BufferedReader reader = 
	         new BufferedReader(new InputStreamReader(p.getInputStream()));
		StringBuilder sb = new StringBuilder();
	    String line = "";			
	    while ((line = reader.readLine())!= null) {
		sb.append(line + "\n");
	    }
		return sb;
	
}
//////////////////////////////////////////////fin/////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////chercher des machine, executer  commande arp-s  et ajout a la table arp///////////////////////////////////////////////////////

public StringBuilder exec_CmdRecheche() throws InterruptedException, IOException{
	/*Process p = Runtime.getRuntime().exec(Command);
	p.waitFor();
	BufferedReader reader = 
	         new BufferedReader(new InputStreamReader(p.getInputStream()));
	         */
		StringBuilder sb = new StringBuilder();
		sb.append("----\n");//
	    sb.append("----\n");//
	    sb.append("----\n");//
	    /////pour ecrir apres la troisieme ligne
		
		
		
		
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // sera remplit avec interface-reseau
		// Nface
		StringBuilder errbuf = new StringBuilder(); // pour tout erreur

		/***************************************************************************
		* 1er. obtenir la list de toutes les interface installé
		**************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
		System.err.printf("impossible de lire la liste desinterfaces, erreur is %s",
		errbuf.toString());
		}
		for (int x = 0; x < alldevs.size(); x++) {
		System.out.println(x + ": " + alldevs.get(x).getDescription());
		}
		PcapIf materiel = alldevs.get(zSpoofer.interface_number);// We know we have atleast 1 materiel
		System.out.printf("\nChoix '%s' :\n",
		(materiel.getDescription() != null) ? materiel.getDescription()
		: materiel.getName());
/*****************************************************************************************************************/
		
		
		
		/***************************************************************************
		* 2eme on ouvre l'interface selectionnée
		**************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 15 * 1000; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(materiel.getName(), snaplen, flags, timeout,
		errbuf);

		if (pcap == null) {
		System.err.printf("Error while opening materiel for capture: "
		+ errbuf.toString());
		}
/***********************************************************************************************************************************/
		
		
		
		

		/***************************************************************************
		3eme creation du packet handler qui va recevoir les packet depuis libpcap
		**************************************************************************/
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
		Ethernet eth = new Ethernet();
		
		public void nextPacket(PcapPacket packet, String user) {
		eth = packet.getHeader(eth);
		String mac = FormatUtils.mac(eth.source());
		byte[] sIP = null;
		String sourceIP = "";
		if (packet.hasHeader(new Ip4()) == true ) {
		sIP = packet.getHeader(new Ip4()).source();
		sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
		
		if (sourceIP.startsWith("192") == true || sourceIP.startsWith("224") == true) {
		if ((!ips.contains(sourceIP)) && (!macs.contains(mac))) {
		ips.add(sourceIP);
		macs.add(mac);
		

		for (int i = 0; i < ips.size(); i++) {
			try{
			
				String line = "";			
			    

			sb.append("\n"+ips.get(i));
			sb.append(" ");
			sb.append(""+macs.get(i).replaceAll(":", "-").toLowerCase());
			
			
			
			
			/*******execution de la commande arp -s************************************************************************/
			Process p = Runtime.getRuntime().exec("arp -s "+ips.get(i)+" "+macs.get(i).replaceAll(":", "-").toLowerCase());
			p.waitFor();
			System.out.println("arp -s "+ips.get(i)+" "+macs.get(i).replaceAll(":", "-").toLowerCase());
			
		    System.out.println(sb);
           /***************************************************************************************************************/
		   
			}catch(Exception e){
				
			}

		
		
		}
		
		}
		}
		}
		}
		};

		/***************************************************************************
	
		*4eme en commence la capture avec dispatch qui prend en compte le time out 
		**************************************************************************/
		pcap.dispatch(50, jpacketHandler, "jNetPcap rocks!");		
		
		/***************************************************************************
		* enfin en ferme
		**************************************************************************/
		pcap.close();
		
		 
		return sb;
	
}
/////////////////////////////////////////////////////////FIN///////////////////////////////////////////////////////////////////////////////////






/////////////////////////////////////////////////afficher la table ARP///////////////////////////////////////////
public String ARP() throws IOException, InterruptedException{
	
	File temp = File.createTempFile("Capture", ".cap"); 
	try{
	temp.deleteOnExit();
	
	}catch(Exception e){
		
	}
	 BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
	    bw.write(new Cmd().exec_Cmd("arp -a").toString());
	    System.out.println(""+temp);
	    bw.close();
   return  temp.getCanonicalPath();
}
/////////////////////////////////////////////FIN////////////////////////////////////////////////////////////////





private static ArrayList<String> ips = new ArrayList<String>();
private static ArrayList<String> macs = new ArrayList<String>();
public static int state=1;





///////////////////////////////////////////////////chercher des machine///////////////////////////////////////

public String Recheche() throws IOException, InterruptedException{

	File temp = File.createTempFile("Capture", ".cap"); 
	try{
	temp.deleteOnExit();
	

	
	}catch(Exception e){
		
	}
	 BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
	    bw.write(new Cmd().exec_CmdRecheche().toString());
	    bw.close();
	    return  temp.getCanonicalPath();
	
}
/////////////////////////////////////////FIN////////////////////////////////////////////////////////////////////




///////////////////////////////////////////////////////////////NOUVELLE MACHINE///////////////////////////////////////
public String NouvDev() throws IOException, InterruptedException{

	File temp = File.createTempFile("Capture", ".cap"); 
	try{
	temp.deleteOnExit();
	

	
	}catch(Exception e){
		
	}
	 BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
	    bw.write(new Cmd().exec_CmdNouveau().toString());
	    bw.close();
	    return  temp.getCanonicalPath();
	
}
////////////////////////////////////////////////////////////////FIN//////////////////////////////////////////////


///////////////////////////////////////CMD POUR AJOUTER A LA TABLE ARP APRES L'AJOUT DE LA NOUVELLE MACHINE//////////////
public StringBuilder exec_CmdNouveau() throws InterruptedException, IOException{
	StringBuilder sb =new StringBuilder();
	try{
		
		String line = "";			
	  /*  while ((line = reader.readLine())!= null) {
	    	
	    }*/
	    

	sb.append("\n");
	sb.append("\n");
	sb.append("\n");
	sb.append("\n");
	sb.append(zSpoofer.nouvDevIP+" "+zSpoofer.nouvDevMac.toLowerCase());
	
	
	
    System.out.println(sb);

   
	}catch(Exception e){
		
	}
	return sb;
}

}