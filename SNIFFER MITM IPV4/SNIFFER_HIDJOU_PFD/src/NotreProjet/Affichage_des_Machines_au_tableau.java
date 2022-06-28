package NotreProjet;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Affichage_des_Machines_au_tableau {
private File Capture;

/**
 * @param capture
 */
public Affichage_des_Machines_au_tableau(File capture) {
	
	Capture = capture;
}
@SuppressWarnings("rawtypes")
////////////////////////////////ajout au tableau du spoofer depuis le fichier capture//////////////////////////////////

public List ReadFromFile() throws IOException{
	List <Machine_Connectée_IP_Mac> materiels_List = new ArrayList<Machine_Connectée_IP_Mac>() ;
		BufferedReader br = new BufferedReader(new FileReader(Capture.getAbsolutePath()));
		String line;
		 FileClass f = new FileClass(Capture);
		 long lines=f.getLines();//nombre des ligne
		 int Machine_number=0;
		 long CurrentLine=1;
		 while((line=br.readLine())!=null){
			 try{
				if(CurrentLine>3 && CurrentLine<=lines-0){
				 Machine_number+=1;
				 String [] materiels = line.trim().split(" ",2);
				 materiels[1]=materiels[1].trim().split(" ",2)[0];
				 
				Machine_Connectée_IP_Mac materiel = new Machine_Connectée_IP_Mac();
				materiel.setNumber(Machine_number);
				materiel.setIP_Address(materiels[0]);
				materiel.setMAC_Address(materiels[1]);
			materiels_List.add(materiel);
				}
				CurrentLine+=1;
			 }catch(Exception e){
				 
			 }
		 }
		   br.close();
return materiels_List;
}


}
