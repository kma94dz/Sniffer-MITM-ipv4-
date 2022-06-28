package NotreProjet;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.swing.JOptionPane;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
public class ListDesInterfaces {  
	
	   
	public List<String> getmaterielsNames() {

	/////////////////////////obtenir la list des interface///////////////////////////////	
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		 String tabB[] = new String[20];
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("impossible de lister, erreur : %s",
					errbuf.toString());
			
		}else{
			

int i = 0;
for (PcapIf materiel : alldevs) {
	String description = (materiel.getDescription() != null) ? materiel
			.getDescription() : "aucune description trouvée!";
	
			
			System.out.println(""+i++ +"-" +materiel.getName()+" "+	description+"\n") ;
			System.out.println(""+i+" "+	description+ " "+"\n") ;
		
}
 }
	  
		
		
		Enumeration<NetworkInterface> interfaces;
		try {
			interfaces = NetworkInterface.getNetworkInterfaces();
		
		List <String> materiels= new ArrayList<String>();
		Commencer_le_Spoofing start = new Commencer_le_Spoofing();
		int number=start.getNics().size();
		int index =0;
		while (interfaces.hasMoreElements() && index<number)
		{
			
		NetworkInterface networkInterface = interfaces.nextElement();
		materiels.add(networkInterface.getDisplayName());
		
		index++;
		}
		
		return materiels;
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			
		}
		return null;
	} 
    }  
  