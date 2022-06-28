package NotreProjet;


import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;

import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper;
import org.jb2011.lnf.beautyeye.ch3_button.BEButtonUI;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
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
import org.jnetpcap.util.checksum.Checksum;
import  org.jfree.chart.ChartFactory;
import  org.jfree.chart.ChartFrame;
import org.jfree.chart.ChartPanel;
import  org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.category.DefaultCategoryDataset;
import  org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.data.xy.XYDataset;
import org.jfree.ui.RefineryUtilities;

import com.alee.laf.WebLookAndFeel;
import com.alee.laf.button.WebButtonStyle;






public class snifferTab extends javax.swing.JFrame implements Observer{
    public static int interface_number=0;
   
    private JButton filtrer = new JButton("FILTRE");
    private JButton spoofer = new JButton(new ImageIcon("right.gif"));
    private JButton detaille = new JButton("Detaille");
    private JButton sniffer = new JButton("SNIFFER");
    private  JButton stop= new JButton("STOP");
    private  JButton spooblock= new JButton("SPOOF");
    private  JButton HeaderFilter= new JButton("HeaderFilter");

    
public static int xli;
static boolean headerFilter=false;
static boolean a=false;
static boolean running=true;
static boolean setstop=false;        
static boolean aleat=true;   

static int interf=0;        

public static JPanel textpanel = new JPanel();

public static List listDesPacket = new LinkedList();//liste des packet capturés

static Pcap pcap;

static JTextArea textPacketDetaille=new JTextArea();

static int proto=0;

    static JButton sniff=new JButton("SNIFFER");
	static DefaultTableModel model = new DefaultTableModel();
   static JTable table = new JTable(model);
   
   
   
   
   ////////////////////////////////////////////////pour l'aide apres click/////////////////////////////////////////
   public static boolean det=true;  public static boolean fil=true;   public static boolean sni=true;
   public static boolean spbl=true;  public static boolean sel=true;  public static boolean sto=true;public static boolean HF=true;
/////////////////////////////////////////////////////////////////////////////////////////////////////////


   
   
   public snifferTab() {
        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        initComponents();
        
    }
                          
    
   
   
   
   
   
   private void initComponents()  {
  		 listDesPacket.add(" ");


  	    

        jLabel1 = new javax.swing.JLabel();
        addPanel = new javax.swing.JPanel();
        Nics = new javax.swing.JComboBox<>();

      jLabel1.setText("              selectionnez une interface :");

        setTitle("SNIFFER | HIDJOU | PFD Promotion 2016");
        setName("Frame"); // NOI18N

       ///////////////////////////////////////////////////pour selectionner une interfece reseau////////////////////////////////////// 
        ListDesInterfaces NICS = new ListDesInterfaces();
        List <String> NameInterface = NICS.getmaterielsNames();
        String []  Items  = new String[NameInterface.size()] ;
        short number=0;
        
        
        for(String materiel:NameInterface){
        	Items[number]=materiel;
        	number+=1;
        }
        Nics.setModel(new javax.swing.DefaultComboBoxModel<>(Items));
        
        Nics.addActionListener(new ActionListener() {
			
			@SuppressWarnings("rawtypes")
			@Override
			public void actionPerformed(ActionEvent e) {
				JComboBox cb = (JComboBox)e.getSource();
		       String Selected_interface=((String)cb.getSelectedItem());
		       for(int index=0;index<NameInterface.size();index++){
		    	  
		    	   if(NameInterface.get(index).equals(Selected_interface)){
		    		   interface_number=index;
		    		   
		    		   
		    		   interf= interface_number;
		    		   
		    		   System.out.println(NameInterface.get(index));
		    		   System.out.println((interface_number));
		    		   
		    	   }
		       }
				
			}
		});
        /////////////////////////////////////////////////////////////FIN//////////////////////////////////////////////////////////////////////////
        
        
        
        
      
        
       sniffer.setUI (new BEButtonUI (). setNormalColor (BEButtonUI.NormalColor.green));
       stop.setUI (new BEButtonUI (). setNormalColor (BEButtonUI.NormalColor.red));
       filtrer.setUI (new BEButtonUI (). setNormalColor (BEButtonUI.NormalColor.blue));
       detaille.setUI (new BEButtonUI (). setNormalColor (BEButtonUI.NormalColor.lightBlue));
       HeaderFilter.setUI (new BEButtonUI (). setNormalColor (BEButtonUI.NormalColor.lightBlue));


       

        
        
        
        
        
        
        
        //////////////////////////////////////////////////////////// le bouton detaille///////////////////////////////////////////////////////////////////////////
        detaille.addActionListener(new ActionListener() {
			
			
			public void actionPerformed(ActionEvent e) {
				try{
					if(det==true){JFrame f=new JFrame();
					JOptionPane.showMessageDialog( f, "le boutton detaille affiche le packet selectioné", "Detaille",
				            JOptionPane.INFORMATION_MESSAGE); det=false;	}
					textPacketDetaille.setText(""+listDesPacket.get(xli));
				}catch(Exception z){
					
				}
		    		   
		    	   
		       
				
			}
		});
        
      
	/////////////////////////////////////////////////////////////////FIN////////////////////////////////////////////////////////////////////////////////////////////	
       

    
        
        
        
        
        
        
        
        
        textPacketDetaille.setEditable(false);

        JPanel Panel = new JPanel();
        
        



        
        
        
        
        
        
     ///////////////////////////////////////////////les columns du tableau/////////////////////////////////////////////////////////
        model.addColumn("num");
        model.addColumn("date");
        model.addColumn("heure");
        model.addColumn("sourceIP");
        model.addColumn("sourceMac");
        model.addColumn("destinationIP");
        model.addColumn("destinationMac");
        model.addColumn("protocole");
        model.addColumn("id");
        model.addColumn("taille");
        model.addColumn("sourcePort");
        model.addColumn("destinationPort");
        table.setBackground(Color.green);
        table.setSelectionBackground(Color.green);
        table.setGridColor(Color.green);
        List l = new LinkedList();
       ////////////////////////////////////////////////////////////FIN/////////////////////////////////////////////////////////////// 
       
     
        
        
    
        
        
        
        
        
        
        
        
        //////////////////////////////////////////////////////////////seclection sur le tableau : : affichage sur textArea/////////////////////  
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener(){
            public void valueChanged(ListSelectionEvent event) {
                // do some actions here, for example
                // print first column value from selected row
            	try{
            	if(sel==true){    
            		JFrame f=new JFrame();
            	
				JOptionPane.showMessageDialog( f, "la selection du packet affiche ses detaille", "selection",
			            JOptionPane.INFORMATION_MESSAGE); sel=false;	}
               
            	
            	xli=(int) table.getValueAt(table.getSelectedRow(), 0);
                System.out.println(xli);
                setSelectedPacketToTextArea();
                
                detaille.setEnabled(true);
				

                

            }catch(Exception e){
            	JFrame f=new JFrame();
            	JOptionPane.showMessageDialog( f, "vas y doucement !!!", "Erreur",
			            JOptionPane.INFORMATION_MESSAGE);
            	setSelectedPacketToTextArea();
            }
            }
        });
        
        /////////////////////////////////////////////////////////FIN///////////////////////////////////////////////////////////////////////////////////////////////
        
        
       
        
        
        
     
        
        
        
        
        
        
        
        
        
        //////////////////////////////////////////////////tableau nn modifiable/////////////////////////////////////////////////////////////////////////////
        for (int c = 0; c < table.getColumnCount(); c++)
        {
            Class<?> col_class = table.getColumnClass(c);
            table.setDefaultEditor(col_class, null);        
        }
        /////////////////////////////////////////////FIN/////////////////////////////////////////////////////////////////////////////////////////////////////
        

     
        
        
        
        JPanel buttonsPanel = new JPanel();
        JPanel autre = new JPanel();
        stop.setEnabled(false);

      
        
        
        
        
        
        
        
        
        
        
        
       
        ///////////////////////////////////////////////////les bouttons/////////////////////////////////////////////////////////
        
        
        sniffer.addActionListener(new ActionListener(){
    		public void actionPerformed(ActionEvent ac){
    			if(sni==true){JFrame f=new JFrame();
				JOptionPane.showMessageDialog( f, "le boutton Sniffer permer de coencer la capture", "Sniffer",
			            JOptionPane.INFORMATION_MESSAGE); sni=false;	}
     			a=true;
    sniffer.setText("SNIFFING");
    sniffer.setEnabled(false);
    filtrer.setEnabled(false);
    stop.setEnabled(true); HeaderFilter.setEnabled(false);
    Nics.setEnabled(false);

    
   
    		}});
        

        
        
        
        
        
        
        
        
        stop.addActionListener(new ActionListener(){
    		public void actionPerformed(ActionEvent ac){

    			try{
    				if(sto==true){JFrame f=new JFrame();
					JOptionPane.showMessageDialog( f, "stop permet d'arreter la capture", "sTop",
				            JOptionPane.INFORMATION_MESSAGE); sto=false;	}
    				pcap.breakloop();
	    		a=false;
    				stop.setEnabled(false);
    				sniffer.setEnabled(true);
    				filtrer.setEnabled(true);
    			    Nics.setEnabled(true);
    			    HeaderFilter.setEnabled(true);

    				sniffer.setText("SNIFFER");
    				
    				


    				
    	    }catch(Exception e){
    	    	
    	    }		}});
        
        
        
        
        
        
        
        
        filtrer.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	if(fil==true){JFrame f=new JFrame();
				JOptionPane.showMessageDialog( f, "le filtre vous permet de choisir quel rotocole capturer", "Filtre",
			            JOptionPane.INFORMATION_MESSAGE); fil=false;	}
            	option();
            }
          });
        
        
        HeaderFilter.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	if(HF==true){JFrame f=new JFrame();
				JOptionPane.showMessageDialog( f, "le Headerfiltre vous permet de choisir quel entete ou tout le packet", "Filtre",
			            JOptionPane.INFORMATION_MESSAGE); HF=false;	}
            	optionHeader();
            }
          });
        
        
        
        
        
        
        spooblock.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	if(spbl==true){JFrame f=new JFrame();
				JOptionPane.showMessageDialog( f, "le boutton spoof permet d'ouvrir le blockeur ou le soofer", "Soof/Block",
			            JOptionPane.INFORMATION_MESSAGE); spbl=false;	}
            	optionspooblock();
            }
          });
        
        
        
        ////////////////////////////////////////////////////////FIN/////////////////////////////////////////////////////////////////
        
        
        
        
     
        
        
        
        
        
        
        
        
        
        
        detaille.setEnabled(false);//boutton Detaille desactivé
        textPacketDetaille.setBackground(Color.white);
        textPacketDetaille.setForeground(Color.black);
        textPacketDetaille.setRows(18);
        textPacketDetaille.setColumns(60);
        textPacketDetaille.setAutoscrolls(isLightweight());
        textPacketDetaille.setLineWrap(true);
      
        textpanel.add(new JScrollPane(textPacketDetaille),BorderLayout.WEST);


       sniffer.setEnabled(true);//boutton Sniffer activé
        JPanel tablePanel = new JPanel();

       buttonsPanel.setBackground(Color.darkGray);
        addPanel.setLayout(new BorderLayout());
        tablePanel.setLayout(new BorderLayout());
       
        
        buttonsPanel.add(filtrer);
        
        textpanel.setBackground(Color.DARK_GRAY);
       
        
        
        
        
        
        JMenuBar menu_bar1 = new JMenuBar();        JMenuBar menu_bar2 = new JMenuBar();



        
        
        
        
        
        
        
        
        
       
        
        
        
        
        
        
        
        
        

////////////////////////////////////////////bare 2///////////on ajoute les boutton dans une menu bar//////////////////////////////
menu_bar2.add(sniffer);
menu_bar2.add(stop);
menu_bar2.add(filtrer);menu_bar2.add(spooblock);
menu_bar2.add(Nics);
menu_bar2.add(detaille);
menu_bar2.add(HeaderFilter);
		/* Ajouter la bar du menu à la frame */
this.setJMenuBar(menu_bar1);



autre.add(menu_bar2,BorderLayout.WEST);
/////////////////////////////////////////////fin menu///////////////////////////////////////////////     
















////////////////ajout des panel////////////////////////////////////////////////////////////////////////////////////////////////
tablePanel.setPreferredSize( new Dimension( 640, 300) );textpanel.setPreferredSize( new Dimension( 1500, 320) );
   tablePanel.add(new JScrollPane(table));

        addPanel.add(textpanel, BorderLayout.SOUTH);
        addPanel.add(buttonsPanel, BorderLayout.NORTH);

        addPanel.add(tablePanel, BorderLayout.CENTER);
        addPanel.add(autre, BorderLayout.NORTH);
             addPanel.setRequestFocusEnabled(true);
    this.add(addPanel);
    /////////////////////////////////////////////////////FIN///////////////////////////////////////////////////////////////////////////
    }
   

   
    
   
   
   
   
   
   
   
   
   
   
   
   
   
   
    
    
    
    
    
    ////////////////////////////////////////////option pour le filtre////////////////////////////////////////////////////
    private void option() {
      
    	 JDialog.setDefaultLookAndFeelDecorated(true);
    	    Object[] selectionValues = { "Ethernet", "IP4", "UDP/TCP/Playload","Aleatoire"};
    	    String initialSelection = "Filtre";
    	    Object selection = JOptionPane.showInputDialog(null, "Choisissez un Protocole",
    	        "Filtre", JOptionPane.QUESTION_MESSAGE, null, selectionValues, initialSelection);
    	    System.out.println(selection);
        
    	    if(selection==selectionValues[0]){
        	proto=0;
        	aleat=false;
        }
if(selection==selectionValues[1]){
        	proto=1;
        	aleat=false;

        }
if(selection==selectionValues[2]){
	proto=2;
	aleat=false;

}
if(selection==selectionValues[3]){
	proto=0;
	aleat=true;

}


      
    }
    
 ////////////////////////////////////////////////////////fin option Filtre//////////////////////////////////////////////////////////////////////////   
    private void optionHeader() {
        
   	 JDialog.setDefaultLookAndFeelDecorated(true);
   	    Object[] selectionValues = { "entete","packet entier"};
   	    String initialSelection = "FiltreHeader";
   	    Object selection = JOptionPane.showInputDialog(null, "Choisissez une option",
   	        "Filtre", JOptionPane.QUESTION_MESSAGE, null, selectionValues, initialSelection);
   	    System.out.println(selection);
       
   	    if(selection==selectionValues[0]){
       	
       	headerFilter=false;
       }
if(selection==selectionValues[1]){
     
	headerFilter=true;
}


     
   }
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
 
    
    
    
    
    
    /////////////////////////spoofer /////////////////////////////////////////////////////////////////////////
    private void optionspooblock() {
        
   	 JDialog.setDefaultLookAndFeelDecorated(true);
   	    Object[] selectionValues = { "Spoofer"};
   	    String initialSelection = "spooblocksend";
   	    Object selection = JOptionPane.showInputDialog(null, "Choisissez une action",
   	        "Spoof/Block", JOptionPane.QUESTION_MESSAGE, null, selectionValues, initialSelection);
   	    System.out.println(selection);
       
   	    if(selection==selectionValues[0]){
       	zSpoofer f=new zSpoofer();
       	f.setVisible(true);
       	f.setResizable(false);
       }




     
   }
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    
  
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    /////////////////////////////////apres la selection dun element au tableau ----affichage du packet dans la TextArea/////////////////////////////////
    public void setSelectedPacketToTextArea(){
    	try{
        textPacketDetaille.setText(""+listDesPacket.get(xli));
    	}catch(Exception z){
    		JFrame f=new JFrame();
        	JOptionPane.showMessageDialog( f, "erreur d'affichage !!! ne scroller pas trop vite", "Erreur",
		            JOptionPane.INFORMATION_MESSAGE);
    	}
    }
    
    
    ////////////////////////////////////////////////////////////////////FIN////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void update(Observable o, Object arg) {
    }

    
    
   
                    
    private javax.swing.JComboBox<String> Nics;
    private javax.swing.JPanel addPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JMenuBar jMenuBar1;
                
   
    static int nr=0;static int tm=0;




    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    /////////////////////////////////////liste de nos interfaces reseaux///////////////////////////////////////////////////////////////////////////////////
static public void ListeMat(){
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		 String tabB[] = new String[80];
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("impossible de lister, erreur : %s",
					errbuf.toString());
			return;
		}else{
			

		
int i = 0;
for (PcapIf device : alldevs) {
	String description = (device.getDescription() != null) ? device.getDescription() : "aucune description trouvée!";
	
			
			System.out.println(""+i++ +"-" +device.getName()+"" +"\n") ;
			System.out.println(""+i+" "+	description+ " "+"\n") ;
		
}
}
	  }
/////////////////////////////////////////////////////////////////FIN/////////////////////////////////////////////////////////////////////////////////////////////////////































static int courbe;static int courbesave;//variable de la courbe





/////////////////////////////////////////sniffer////////////////////////////////////////////////////////////////////////////////////////////////////////////
public static void sniff(){	
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		// 
		StringBuilder errbuf = new StringBuilder(); // pour les erreurs
		int r = Pcap.findAllDevs(alldevs, errbuf);
		
		LocalDate ld = LocalDate.now();
		LocalTime lt = LocalTime.now();
		System.out.println("\n ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Capture : ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Capture : /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// \n");
		System.out.println("date : "+ld+"\n" );
		System.out.println("heure : "+lt+"\n" );
		
		//****************ouvrir le divice selectioné***************//
		interf= interface_number;
		PcapIf device = alldevs.get(interf);
		
		int snaplen = 64 * 1024; // capturer tout le packet
		int flags = Pcap.MODE_PROMISCUOUS; // tout
		int timeout = 15 * 1000; // 
		pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		if (pcap == null) {
			System.out.println("\n Erreur lors de louverture: "
					+ errbuf.toString()+"\n");
			JOptionPane.showMessageDialog(null, "erreur lors de l'ouverture ");
			
			
			return;
		}
		//****************FIN***************************************//
		
		
		
		
		
		//***********creation du packet handler qui va recevoire les paquet depuis LibCap loop********//
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			
			public void nextPacket(PcapPacket packet, String user) {
				
			   Ip4 ip2 = new Ip4();
               Ethernet eth=new Ethernet();
               Tcp tcp=new Tcp();
               Udp udp=new Udp();
               
               String sIP2;//sourceIP
               String dIP2;//destinationIP
               
               String msIP2;//Macsource
               String mdIP2;//DestinationMac
               
               
               int totalLength=0;
              
               
               
               
               
               
               
               ////////////////////////////////////////si ya un header ip///////////////////////////////////////////
               if (packet.hasHeader(ip2) == false){
               	System.out.println("erreur header");
               	pcap.breakloop();
                   return;
               }else{
                totalLength = totalLength+ ip2.getPayloadLength();
                sIP2 = org.jnetpcap.packet.format.FormatUtils.ip(ip2.source());
                dIP2 = org.jnetpcap.packet.format.FormatUtils.ip(ip2.destination());
               System.out.println(packet.getHeader(ip2));
              
               }
                ///////////////////////////////////////////////////////////////////////////////////////////////////////
               
               
               
               
               
              
               
               
               
               ////////////////////////////////si ya un header ethernet/////////////////////////////////////////
               if (packet.hasHeader(eth) == false){
                  	System.out.println("erreur header");
                  	pcap.breakloop();
                      return;
                  }else{
                   totalLength = totalLength+ eth.getPayloadLength();
               
                   msIP2 = org.jnetpcap.packet.format.FormatUtils.mac(eth.source());
                   mdIP2 = org.jnetpcap.packet.format.FormatUtils.mac(eth.destination());
                 
                  }
               ////////////////////////////////////////////////////////////////////////////////////////////////////
          
				
               
               
               
               
               
               
               
               
               
               
               
              //compter les header// /////////////////////////////////////////////////////////////
               final JHeaderPool headers = new JHeaderPool();  
                final int count = packet.getHeaderCount();  
                for (int i = 0; i < count; i++) {  
                  final int id = packet.getHeaderIdByIndex(i); // Numerical ID of the header  
                  final JHeader header = headers.getHeader(id); //id du header 
                  final String name = header.getName();  //nom du header(affiche le protocole
                  final String nicname = header.getNicname();  //surnom
                  final String description = header.getDescription();  //description
                  final JField[] fields = header.getFields();  //champ
                  final AnnotatedHeader annotatedHeader = header.getAnnotatedHeader(); // Annotation
                 
                }
                /////////////////fin//////////////////////////////////////////////////////////////
                
                
               
                
                
                
                
                
                
                //////choix eth ip  tcp/udp/data(playload)//////
                int id = packet.getHeaderIdByIndex(proto);
                ///////////////////////FIN/////////////////////
                
                
                
                
                
                JHeaderPool headerPool = new JHeaderPool();

                

                
             
               
                JHeader header = headerPool.getHeader(id);//capturer le protocol.....
                
               String port = null;                 String portD = null;               
             

               
               
               
               
               //////////////////////////////////obtenir les port source et destination/////////////////////////////
               if(packet.hasHeader(new Tcp()))
               {
                    tcp = packet.getHeader(new Tcp());
                   port=""+ tcp.source();
                   portD=""+tcp.destination();
              		System.out.println("tcp : "+port);

               }
            
            


               if(packet.hasHeader(new Udp()))
               {
                    udp = packet.getHeader(new Udp());
                   port=""+ udp.source();
                   portD=""+udp.destination();              		System.out.println(port);

               }
               
               //////////////////////////////////////FIN//////////////////////////////////////////////////////////////////

               

                        
                    
nr++;//nombre de packets
                
   			
   			LocalDate ld2 = LocalDate.now();//date
   			LocalTime lt2 = LocalTime.now();//heure
   			
   			
   			
   			
   			
   			
   			
   			
   			///////////////////////////////obtenir DATA du packet////////////////////////////////////////
   			String hexdump = packet.toHexdump(packet.size(), false, false, true);  
   		  
   			byte[] data = FormatUtils.toByteArray(hexdump);  
   			  
   			JMemory packetDATA = new JMemoryPacket(JProtocol.ETHERNET_ID, data);  
   		 ////////////////////////////////////////////////////////////FIN/////////////////////////////////////
   			
   			
   			
   			
   			
   			
   			
   			if(headerFilter==false && id == 1){
   			listDesPacket.add(packet.getHeader(eth));//mettre entete dans la liste
   			}
   			if(headerFilter==false && id == 2){
   	   			listDesPacket.add(packet.getHeader(ip2));//mettre entete dans la liste
   	   			}
   			if(headerFilter==false && id == 4){
   	   			listDesPacket.add(packet.getHeader(tcp));//mettre entete dans la liste
   	   			}
   			if(headerFilter==false && id == 5){
   	   			listDesPacket.add(packet.getHeader(udp));//mettre entete dans la liste
   	   			}
   			
   			
   			if(headerFilter==true){
   	   			listDesPacket.add(packetDATA);//mettre les data dans la liste
   	   			}
   		 System.out.println(packetDATA);
   		 System.out.println("data"+data);

   		
   		
   		
  			 table.setBackground(Color.DARK_GRAY);
  			 table.setForeground(Color.WHITE);
  			
  			 try{
  				 Thread.sleep(2000);
  			 }catch(Exception e){
  				 
  			 }
  			 
  			 
  			 
  			 
  			 
  			 
  			 /////////////////////////////////////////////////afficher dans le tableau/////////////////////////////////////////////
   			model.addRow(new Object[] { nr,ld2, lt2,sIP2,msIP2,dIP2,mdIP2,header.getName(),id,packet.size(),port,portD });
   		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
   			
   			
   			courbesave=courbe;
  		 courbe=packet.size();//la courbe egale a la taille des packets
  		 
  		 System.out.println(courbe);
  		action();//methodes de la courbe
              
              
           }  
       };  
       
      
       
       
      
       
       
       
       
       
       
       
       ///**********nb de paquet a scapturer**********//
pcap.loop(10, jpacketHandler, "jNetPcap rocks!");//////////en capture un packet::::::
		
pcap.close();////on ferme::::: apres la capture
		
		
			if(aleat==true){//////////////:si aleatoir est choisi:::
				proto=proto+1;///////a chaque fois on change de protocol:::
				
				if(proto==3){/////si la variable est egale a 3 on recommence depuis le debut::::
					proto=0;
				}
				
			}
			
	

		// 
    
    
    
    }


















///////////////////////////////////////////////JFreeChart.......LA courbe///////////////////////////////////////////////////////////////////////////
private static TimeSeries series;
private static double lastValue = 0.0;





///////////////////////////////Class de la courbe//////////////////////////////
public static void DynamicLineAndTimeSeriesChart(final String title) {

	series = new TimeSeries("Packets", Millisecond.class);
    final TimeSeriesCollection dataset = new TimeSeriesCollection(series);
    final JFreeChart chart = createChart(dataset);


    //backgroud du satatistique
    chart.setBackgroundPaint(Color.white);
    
    //Creation JPanel pour afficher le statistique 
    final JPanel content = new JPanel(new BorderLayout());

    //Creation Chartpanel pour la courbe
    final ChartPanel chartPanel = new ChartPanel(chart);

    //ajouter chartpanel
    content.add(chartPanel);

    //taille du statistique
    chartPanel.setPreferredSize(new java.awt.Dimension(800, 300));

    //mettre tout dans le frame
textpanel.add(content, BorderLayout.EAST);
    

}
//////////////////////////////////////////////////////////////////////////////









///////////////////////////////////creation de la courbe/////////////////////////////////////////////
private static JFreeChart createChart(final XYDataset dataset) {
    final JFreeChart result = ChartFactory.createTimeSeriesChart(
        "Statistique",
        "Time",
        "Size",
        dataset,
        true,
        true,
        false
    );
    final XYPlot plot = result.getXYPlot();
    plot.setBackgroundPaint(Color.black);
    plot.setDomainGridlinesVisible(true);
    plot.setDomainGridlinePaint(Color.green);
    plot.setRangeGridlinesVisible(true);
    plot.setRangeGridlinePaint(Color.green);
    ValueAxis xaxis = plot.getDomainAxis();
    xaxis.setAutoRange(true);

    //donnée en 15 sec
    xaxis.setFixedAutoRange(150000.0);  // 60 seconds
    xaxis.setVerticalTickLabels(true);

    ValueAxis yaxis = plot.getRangeAxis();
    yaxis.setRange(0.0, 700.0);

    return result;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////








///////////////////////////////methode pour modifier la courbe////////////////////////////////////////////////////
public static void action() {

    final double factor =  courbe;
    lastValue =  factor;

    final Millisecond now = new Millisecond();
    series.add(new Millisecond(), lastValue);

    System.out.println("Current Time in Milliseconds = " + now.toString()+", Current Value : "+lastValue);
}
//////////////////////////////////////////FIN/////////////////////////////////////////////////////////////////////////
	 


























///////////////////////////////////////////////////////////////////MAIN/////////////////////////////////////////////////////////////////////
public static void main(String args[]) throws Exception {
		try {
	        	

	        	BeautyEyeLNFHelper.frameBorderStyle = BeautyEyeLNFHelper.FrameBorderStyle.osLookAndFeelDecorated;
	        	UIManager . put ( "RootPane.setupButtonVisible" ,  false );
	            org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper.launchBeautyEyeLNF();
	        
	        } catch (ClassNotFoundException ex) {
	            java.util.logging.Logger.getLogger(snifferTab.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	        } catch (InstantiationException ex) {
	            java.util.logging.Logger.getLogger(snifferTab.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	        } catch (IllegalAccessException ex) {
	            java.util.logging.Logger.getLogger(snifferTab.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
	            java.util.logging.Logger.getLogger(snifferTab.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	        }
	      
		 
	/*	java.awt.EventQueue.invokeLater ( new Runnable ()
	        {
	            public void run ()
	            {
	                // Install WebLaF as application L&F
	            	WebLookAndFeel.install(true); WebLookAndFeel.setDecorateAllWindows(true);
	            	 WebButtonStyle.topSelectedBgColor = Color.red;
	                 WebButtonStyle.bottomSelectedBgColor = Color.red;
	                 WebLookAndFeel.install (); 
	        		 snifferTab lunch = new snifferTab();

	     	        JOptionPane.showMessageDialog(lunch,"notre programme doit pouvoir ajouter des IP et des Mac a la table arp, assurez vous que eclipse est sous mode administrateur");
     	
	        		 lunch.setLocation(100,60);
	        	     	lunch.setSize(1500,680);
	        	     	lunch.setVisible(true);
	                 
	                // Create you Swing application here
	                // JFrame frame = ...
	            }
	        } );*/



		

		 snifferTab lunch = new snifferTab();
		 DynamicLineAndTimeSeriesChart("Statistique");
		 JOptionPane.showMessageDialog(lunch,"notre programme doit pouvoir ajouter des IP et des Mac a la table arp, assurez vous que eclipse est sous mode administrateur");
		 JOptionPane.showMessageDialog(lunch, "projet de Fin d'etude :Man In The Middle Attack", "PFD",
		            JOptionPane.INFORMATION_MESSAGE);	
		lunch.setLocation(5,60);
	     	lunch.setVisible(true);
	     	lunch.setResizable(false);
	     
	     	lunch.pack();
	            	try{
	            		//////////////////////attendre que le bouton sniffer soit clické::::::::::::::::::::::::::::
	                	while(a==false){
	                		Thread.sleep(200);
	                	}
	                }catch(Exception e){
	                	
	                }
	            	
	            	
	            	
	          
	     
/////////////////////////////////////////////////////while infini running////////////////////////////////////////////////
	            	while(running==true){
	            		try{
	            	    sniff();
	            	   
	            	    while(a==false){//si stop est clické
	            	    	
	            			Thread.sleep(200);///////////////////on attend que le bouton sniffer soit de nouveau clické
	            		
	            		}

	            	    }catch(Exception e){
	            	    	
	            	    	Thread.sleep(3000);
	            	    	sniff();
	            	    }
	            	}
	
/////////////////////////////FIN while running///////////////////////////////////////////////////////////////////////////


}}
	            
	        
	    
	 
	 

	

	 
	 


