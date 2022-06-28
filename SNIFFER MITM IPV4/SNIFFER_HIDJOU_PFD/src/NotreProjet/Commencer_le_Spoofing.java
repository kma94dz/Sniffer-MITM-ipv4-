package NotreProjet;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JOptionPane;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class Commencer_le_Spoofing {
	 
	private static final int snaplen = 64 * 1024;//tout le packet
	 private static final int flags = Pcap.MODE_PROMISCUOUS;
	 private static final int timeout = 10 * 1000;
	StringBuilder errbuf = new StringBuilder();
	
	public List <PcapIf> getNics(){
	List<PcapIf> alldevs = new ArrayList<PcapIf>();
    
    int r = Pcap.findAllDevs(alldevs, errbuf);
    if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
    	JOptionPane.showMessageDialog(null, "impossible de lire la liste des interfaces \n"+ errbuf.toString(), "Error(materiels)", JOptionPane.ERROR_MESSAGE);
    }
    
    return alldevs; 
}
	
	
	/////////////////////preparrer le materiel//////////////////////////////
	public PcapIf  Preparer_materiel(List <PcapIf> Nics,int NICnumber){
		 return Nics.get(NICnumber);
		    
	}
	////////////////////////////////////////////////////////////////////////
	
	
	///////////////////////////envoyer le packet/////////////////////////////////////////////
	public void Envoyer_Frame(PcapIf materiel,ByteBuffer a){
		Pcap pcap = Pcap.openLive(materiel.getName(), snaplen, flags, timeout, errbuf);
		if (pcap.sendPacket(a) != Pcap.OK) {
			JOptionPane.showMessageDialog(null, "Not sent \n"+ pcap.getErr(), "Error d'envoi", JOptionPane.ERROR_MESSAGE);
	   }
	}
	/////////////////////////////////////////////////////////////////////////////////////////////
}