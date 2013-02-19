package cat.urv.crises.smartcard.elgamal;
/* 
 * Copyright (c) 2013, Universitat Rovira i Virgili
 * All rights reserved.
 * 
 * The license for this file is based on the BSD-3-Clause license
 * (http://www.opensource.org/licenses/BSD-3-Clause).
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * - Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * - Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 * 
 * - Neither the name of the Universitat Rovira i Virgili nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * 
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 * This work has been developed within the project eVerification2 TSI-020100-2011-39,
 * leaded by Scytl Secure Electronic Voting S.A. and supported by the Spanish 
 * Ministry of Industry, Commerce and Tourism (through the development program AVANZA 
 * I+D). We would like to thank Scytl for their support and to the Ministery for the 
 * needed founding required to carry it out.
 * The Beta version of this code has been implemented by Jordi Castellà, Vicenç Creus, 
 * Roger Jardí and Jordi Pujol ([jordi.castella,vicenc.creus,roger.jardi,jordi.pujol]@urv.cat).
 * 
 */
import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import javax.swing.JLabel;
import java.awt.FlowLayout;
import java.awt.ComponentOrientation;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import javax.swing.JTextArea;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
/**
 * Interface of use cases implemented in the SC
 * 
 * @author Roger Jardí Cedó {@link roger.jardi@urv.cat} & Vicenç Creus Garcia {@link vicens.creus@urv.cat}
 */
public class Principal extends JFrame implements PropertyChangeListener{
	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private final int max=10;
	private CardTerminal[] terminal = new CardTerminal[max];
	private List<CardTerminal> terminals;
	private TerminalFactory factory;
	private String[] listerminals=null;
	private ArrayList<JCheckBox> smartchecks;
	private ArrayList<JButton> verifsbtns;
	private JButton verifallbtn;
	private static CardClient cc;
	private JFrame frame;
	private Task task;
	private Taskencrypt taskncrypt;
	private Taskdecrypt taskdcrypt;
	private TaskencryptSim taskencryptsim;
	private TaskdecryptSim taskdecryptsim;
	private int numMax;
	private String message="";
	private int nn;
	private int ids;
    private JTextArea taskOutput;
    private String missatgeteclat;
    private JTextField jtxt;
    private static SimpleDateFormat sdf;
    private JSpinner spP1;
    private JSpinner spP2;
    private JSpinner spP3;
    private JPanel pnl_simulate;
    private JButton btnXifra; 
    private JButton btntally;
    private JButton genera, btnSimularVoting, btnRecompte ; 
    private JPanel panel_2, panel ;
    private JLabel mplir;
    private ArrayList<Integer> primers; 


	/**
	 * Create the frame for use cases, verification, encrypt, decrypt and voting simulation.
	 * @throws CardException 
	 */
	public Principal(final CardClient cct) throws CardException {

		cc=cct;
		primers =new ArrayList<Integer>();
		primers.add(5);
		primers.add(3);
		primers.add(2);
		sdf  = new SimpleDateFormat("mm:ss.SSS");
		frame = new JFrame();
		frame.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
        frame.getContentPane().setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        
        JPanel panel_4 = new JPanel();
        frame.getContentPane().add(panel_4);
        panel_4.setLayout(new BorderLayout(0, 0));
        
        JLabel lblEscullLesSmart = new JLabel("Choose the SC to use:                                                                                              ");
        panel_4.add(lblEscullLesSmart, BorderLayout.NORTH);
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 3, 5));
        frame.getContentPane().add(contentPane);
        contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
        contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
        
        panel = new JPanel();
        panel.setBorder(new EmptyBorder(20, 0, 0, 0));
        panel.setLayout(new BorderLayout(0, 0));
        
        JPanel panel_1 = new JPanel();
        panel.add(panel_1, BorderLayout.NORTH);
        panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.Y_AXIS));
        
        panel_2 = new JPanel();
        panel_1.add(panel_2);
        GridBagLayout gbl_panel_2 = new GridBagLayout();
        gbl_panel_2.columnWidths = new int[]{60, 30, 276, 20};
        gbl_panel_2.rowHeights = new int[]{23, 0};
        gbl_panel_2.columnWeights = new double[]{1.0, 0.0, 0.0, 0.0};
        gbl_panel_2.rowWeights = new double[]{0.0, Double.MIN_VALUE};
        panel_2.setLayout(gbl_panel_2);
        
        JLabel txt = new JLabel("message: ");
        GridBagConstraints gbc_txt = new GridBagConstraints();
        gbc_txt.anchor = GridBagConstraints.WEST;
        gbc_txt.insets = new Insets(0, 0, 0, 5);
        gbc_txt.gridx = 0;
        gbc_txt.gridy = 0;
        panel_2.add(txt, gbc_txt);
        jtxt = new JTextField();
        GridBagConstraints gbc_jtxt = new GridBagConstraints();
        gbc_jtxt.anchor = GridBagConstraints.WEST;
        gbc_jtxt.insets = new Insets(0, 0, 0, 5);
        gbc_jtxt.gridx = 2;
        gbc_jtxt.gridy = 0;
        panel_2.add(jtxt, gbc_jtxt);
        jtxt.setColumns(42);
        jtxt.setSize(20,20);
        
        JPanel pnl_sep = new JPanel();
        frame.getContentPane().add(pnl_sep);
        
        JLabel lblNewLabel = new JLabel("_______________________________________________________________________________");
        pnl_sep.add(lblNewLabel);
        
        JPanel panel_3 = new JPanel();
        panel_3.setBorder(new EmptyBorder(2, 0, 0, 0));
        panel_1.add(panel_3);
        panel_3.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        
        genera = new JButton("Generate");
        panel_3.add(genera);
        genera.addActionListener(new ActionListener(){

			@Override
			public void actionPerformed(ActionEvent arg0) {
				if(pnl_simulate.isVisible()){
					pnl_simulate.setVisible(false);
					frame.setSize(620, 700);
				}
				missatgeteclat = jtxt.getText();
				System.out.println("TECLAT: "+missatgeteclat);

				taskOutput.setText("");
				taskOutput.append("MESSAGE GENERATION\n");
				taskOutput.append("------------------------------------------------\n\n");
				taskOutput.append("Message generation...");
				if(missatgeteclat.equals("")){
					long ini = System.currentTimeMillis();
					cc.createMessage();  
					//str = cc.getMtoString();
					taskOutput.append("\t\t   OK\n");
					jtxt.setText(cc.getMtoString());
					missatgeteclat=cc.getMtoString();
					long fi = System.currentTimeMillis();
					taskOutput.append("\nTime of generation: "+sdf.format(fi-ini));
				}else if(missatgeteclat.isEmpty()==false){
				
					//BigInteger introteclat = new BigInteger(missatgeteclat);
					cc.createMessageBox(missatgeteclat);
					if(cc.getM().bitLength()<(cc.getPbitLength()-1)){
						long ini = System.currentTimeMillis();
						//cc.createMessageBox(missatgeteclat);
						//str = cc.getMtoString();
						taskOutput.append("\t\t   OK\n");
						long fi = System.currentTimeMillis();
						taskOutput.append("Time of generation: "+sdf.format(fi-ini));
					}else{
						taskOutput.setText("");
						JOptionPane.showMessageDialog(Principal.this, "Message too longer");
					}
						
				}
				//jtxt.setText(str);
				//gtasks = new GenerateTasks();
			    //gtasks.addPropertyChangeListener(ParaProvar.this);
			    //gtasks.execute();
			}
        	
        });
        
        btnXifra = new JButton("Encrypt");
        panel_3.add(btnXifra);
        btnXifra.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				taskncrypt = new Taskencrypt();
			  	taskncrypt.addPropertyChangeListener(Principal.this);
				taskncrypt.execute();
			}
        	
        });
        
        btntally = new JButton("Decrypt");
        btntally.setEnabled(false);
        panel_3.add(btntally);
        
        mplir = new JLabel("            ");
        panel_3.add(mplir);
        
        btnSimularVoting = new JButton("Voting simulation");
        panel_3.add(btnSimularVoting);
        btnSimularVoting.addActionListener(new ActionListener(){

			@Override
			public void actionPerformed(ActionEvent arg0) {
				taskOutput.setText("");
				if(btnXifra.isVisible()){
					panel_2.setVisible(false);
					btnXifra.setVisible(false);
					genera.setVisible(false);
					btntally.setVisible(false);
					btnRecompte.setEnabled(false);
					mplir.setText("            ");
					mplir.setText("                                                                 ");
				}else{
					taskOutput.setText("");
					panel_2.setVisible(true);
					btnXifra.setVisible(true);
					genera.setVisible(true);
					btntally.setVisible(true);
					btntally.setEnabled(false);
					mplir.setText("            ");
					
				}
				jtxt.setText("");
				if(pnl_simulate.isVisible()==false){
					pnl_simulate.setVisible(true);
					frame.setSize(620, 785);
				}else{
					pnl_simulate.setVisible(false);
					frame.setSize(620, 700);
				}
			}
        	
        });
        
        btntally.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				/*frame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
				WaitDisable();
				try {
					long ini = System.currentTimeMillis();
					int[] ids = ParaProvar.this.selectedNumbers();
					int number=ParaProvar.this.numbMarked(ids);
					if(number >=3){
						Integer[] newArray = new Integer[number];
						int i =0;
						while (i<ids.length && ids[i]!=-1) {
							newArray[i] = Integer.valueOf(ids[i]);
							i++;
						}
						for(int ix=0; ix<newArray.length;ix++){
							System.out.println(newArray[ix]);
						}						
						taskOutput.setText("");
						taskOutput.append("DECRYPTION MESSAGE\n");
						taskOutput.append("------------------------------------------------\n\n");
						taskOutput.append("Desxifrant missatge...");
						cc.useTally(newArray);
						String sw =cc.getResponsesw()[0];
						if(sw.equals("9000")){
							taskOutput.append("\t\t   OK\n");
						}else{
							taskOutput.append("\t\t   ERROR: "+sw+"\n");
						}
						taskOutput.append("Message esperat:  "+cc.getMtoString());
						taskOutput.append("\nMissatge obtingut: "+cc.getDECtoString());
						long fi = System.currentTimeMillis();
						taskOutput.append("\n\nTime of decryption: "+sdf.format(fi-ini));
					}else{
						JOptionPane.showMessageDialog(ParaProvar.this, "Num tally minim 3 SC");
					}
				} catch (CardException e) {
					System.out.println(e);
				}
				frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
				StartEnable();*/
				taskdcrypt = new Taskdecrypt();
			  	taskdcrypt.addPropertyChangeListener(Principal.this);
				taskdcrypt.execute();
			}
        	
        });
        frame.getContentPane().add(panel);
        
        pnl_simulate = new JPanel();
        frame.getContentPane().add(pnl_simulate);
        pnl_simulate.setLayout(new BoxLayout(pnl_simulate, BoxLayout.Y_AXIS));
        JPanel pnlpartit1 = new JPanel();
        pnl_simulate.add(pnlpartit1);
        
        JLabel lblP1 = new JLabel("Votes for the party 1                                            ");
        pnlpartit1.add(lblP1);
        
        spP1 = new JSpinner();
        spP1.setModel(new SpinnerNumberModel(1, 1, 100, 1));
        pnlpartit1.add(spP1);
        
        JPanel pnlpartit2 = new JPanel();
        pnl_simulate.add(pnlpartit2);
        
        JLabel lblP2 = new JLabel("Votes for the party 2                                            ");
        pnlpartit2.add(lblP2);
        
        spP2 = new JSpinner();
        spP2.setModel(new SpinnerNumberModel(1, 1, 100, 1));
        pnlpartit2.add(spP2);
        
        JPanel pnlpartit3 = new JPanel();
        pnl_simulate.add(pnlpartit3);
        
        JLabel lblP3 = new JLabel("Votes for the party 3                                            ");
        pnlpartit3.add(lblP3);
        
        
        spP3 = new JSpinner();
        spP3.setModel(new SpinnerNumberModel(1, 1, 100, 1));
        pnlpartit3.add(spP3);
        
        JPanel pnl_ok = new JPanel();
        FlowLayout flowLayout = (FlowLayout) pnl_ok.getLayout();
        flowLayout.setAlignment(FlowLayout.RIGHT);
        pnl_simulate.add(pnl_ok);
        
        JButton btnXifra2= new JButton("Encrypt");
        pnl_ok.add(btnXifra2);
        btnXifra2.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				taskencryptsim = new  TaskencryptSim();
				taskencryptsim.addPropertyChangeListener(Principal.this);
				taskencryptsim.execute();
			}
        	
        });
        btnRecompte = new JButton("Decrypt");
        btnRecompte.setEnabled(false);
        pnl_ok.add(btnRecompte);
        btnRecompte.addActionListener(new ActionListener(){

			@Override
			public void actionPerformed(ActionEvent arg0) {		
				taskdecryptsim = new  TaskdecryptSim();
				taskdecryptsim.addPropertyChangeListener(Principal.this);
				taskdecryptsim.execute();
			}        	
        });

        
        JButton btnCancel = new JButton("Cancel");
        pnl_ok.add(btnCancel);
        pnl_simulate.setVisible(false);
        btnCancel.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				taskOutput.setText("");
				panel_2.setVisible(true);
				btnXifra.setVisible(true);
				genera.setVisible(true);
				btntally.setVisible(true);
				btntally.setEnabled(false);
				btnRecompte.setEnabled(false);
				mplir.setText("            ");
				spP1.setValue(1);
				spP2.setValue(1);
				spP3.setValue(1);
				pnl_simulate.setVisible(false);
				frame.setSize(620, 700);
			}
        	
        });

        JPanel pnlArea = new JPanel();
        pnlArea.setBorder(new EmptyBorder(10, 0, 0, 0));
        frame.getContentPane().add(pnlArea);
        
        taskOutput = new JTextArea(15, 50);
        taskOutput.setMargin(new Insets(5,5,5,5));
        taskOutput.setEditable(false);
        pnlArea.add(new JScrollPane(taskOutput), BorderLayout.CENTER);
       
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setTitle("("+cc.getTHRESHOLD()+","+cc.getNumShares()+") - ElGamal Threshold Scheme ["+cc.getPbitLength()+" bits]");
		frame.setBounds(5, 5, 300, 250);
		this.smartchecks = new ArrayList<JCheckBox>();
		this.verifsbtns = new ArrayList<JButton>();
		this.listTerminals();
		frame.setSize(620, 700);
		setSize(620, 700);
        Dimension pantalla = Toolkit.getDefaultToolkit().getScreenSize();
        Dimension ventana = frame.getSize();
        System.out.println(frame.getSize()+", panatallalaa "+pantalla);
       
        frame.setLocation((pantalla.width - ventana.width) / 2,(pantalla.height - ventana.height) / 2);
		frame.setVisible(true);
	}
	
	private void cleanCheckBoxes(){
		for(int i=0;i<this.smartchecks.size();i++){
			this.smartchecks.get(i).setSelected(false);
		}
	}
	/**
	 * Lock clickable components 
	 */
	private void WaitDisable(){
		genera.setEnabled(false);
		btnSimularVoting.setEnabled(false);
		btntally.setEnabled(false);
		btnXifra.setEnabled(false);
		verifallbtn.setEnabled(false);
		jtxt.setEditable(false);
		for(int i=0;i<verifsbtns.size();i++){
			verifsbtns.get(i).setEnabled(false);
		}
		for(int i=0;i<smartchecks.size();i++){
			smartchecks.get(i).setEnabled(false);
		}
	}
	/**
	 * Unlock clickable components 
	 */
	private void StartEnable(){
		//panel.setEnabled(true);
		//pnl_simulate.setEnabled(true);
		genera.setEnabled(true);
		btnSimularVoting.setEnabled(true);
		btntally.setEnabled(true);
		btnXifra.setEnabled(true);
		verifallbtn.setEnabled(true);
		jtxt.setEditable(true);
		for(int i=0;i<verifsbtns.size();i++){
			verifsbtns.get(i).setEnabled(true);
		}
		for(int i=0;i<smartchecks.size();i++){
			smartchecks.get(i).setEnabled(true);
		}
	}
	

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if ("progress" == evt.getPropertyName()) {
            int progress = (Integer) evt.getNewValue();
            //inicialitza el generador
            if(progress==19){
            	if(this.numMax!=1){
            		taskOutput.append("   Smart Card "+0+"\n");
            	}else{
            		taskOutput.append("   Smart Card "+nn+"\n");
            	}
            	//setProgress(0);
            }else if(progress>=0 && progress < cc.getNumShares()-1 && numMax!=1){
            	taskOutput.append("            "+message);
            	taskOutput.append("------------------------------------------------\n");

            	taskOutput.append("   Smart Card "+(progress+1)+"\n");
            }else if(progress == cc.getNumShares()-1 || this.numMax==1){
            	taskOutput.append("            "+message);
            }else if(progress==30){
            	
            }
            
        }
		
	}
	/**
	 * List the terminals
	 * @throws CardException
	 */
	private void listTerminals() throws CardException{
		//extract all terminals
		for(int i=0;i<max;i++){
			if (terminal[i] == null){
				factory = TerminalFactory.getDefault(); //uses SunPCSC; the unique available to interact with PC/SC stack.
				terminals = factory.terminals().list();
			}
		}
		listerminals= new String[terminals.size()];
		Arrays.fill(listerminals, "-1");
		int j = 0;
		//of all terminals, only catch the names
		for (CardTerminal t:terminals){
			System.out.println(j + " - Terminal: " + t.getName()+ " es present: "+ t.isCardPresent() );
				listerminals[j]=t.getName();		
			j++;
		}
		String[]llista =null;
		try{
			llista =SCUsedToCheckBoxes();
		}catch(ArrayIndexOutOfBoundsException aioobe){
			JOptionPane.showMessageDialog(Principal.this, "Suspicious reader disconnection ");
			System.exit(0);
		}
		for (int i=0; i<llista.length;i++){
			JPanel temp = new JPanel(new BorderLayout());
			JCheckBox check =new JCheckBox(llista[i]);
			check.setBorder(new EmptyBorder(9,15,5,0));
			this.smartchecks.add(check);
			final int n=i;
			JButton bot = new JButton("Verify");
			bot.addActionListener(new ActionListener(){
				@Override
				public void actionPerformed(ActionEvent arg0) {
					smartchecks.get(n).setSelected(true);
					int[] ides = Principal.this.selectedNumbers();
					ids=ides[0];
					System.out.println(ides[0]+"  ids");
					int number=Principal.this.numbMarked(ides);
					if(number==1){
						//try {
						nn= Principal.this.selectedNumber();
						numMax=1;
						ids=ides[0];
						taskOutput.setText("");
					    task = new Task();
					    task.addPropertyChangeListener(Principal.this);
					    task.execute();
						cleanCheckBoxes();
					}else if(number >1){
						JOptionPane.showMessageDialog(Principal.this,"Only can verify one SC");
						cleanCheckBoxes();
					}else if(number <1){
						JOptionPane.showMessageDialog(Principal.this,"At least mark a SC");
					}
				}
			});
			this.verifsbtns.add(bot);
			temp.add(check,BorderLayout.WEST);
			temp.add(verifsbtns.get(i),BorderLayout.EAST);
			if(i+1==llista.length){
				this.verifallbtn = new JButton("Verify all SC");
				verifallbtn.addActionListener(new ActionListener(){
					@Override
					public void actionPerformed(ActionEvent ae) {
						WaitDisable();
						frame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
						taskOutput.setText("");
						numMax = cc.getCards().length;
						//task = new Task();
					  	//task.addPropertyChangeListener(ParaProvar.this);
						//task.execute();
						
						/* **********CONCURRENCIA******************************************************************* */
						ArrayList<SCVerification> scverifcationState= new ArrayList<SCVerification>();
						long inis = System.currentTimeMillis();
						taskOutput.append("VERIFICATION OF THE SC\n");
		            	taskOutput.append("------------------------------------------------\n\n");
						
						for(int i=0;i<cc.getCards().length;i++){
							nn= i;
							numMax=1;
							ids=i;
							
						//	task = new Task();
						//  	task.addPropertyChangeListener(ParaProvar.this);
						//	task.execute();
							
							SCVerification sverifica = new SCVerification(cc, i, i, taskOutput, genera, btntally, btnSimularVoting, btnXifra, verifallbtn, verifsbtns, smartchecks, jtxt);
							scverifcationState.add(sverifica);
							sverifica.start();
						}
						//boolean deathall=false;

						//System.out.println("NOFINAL:"+nofinal+" mida "+scverifcationState.size());
						for(int ic=0; ic<scverifcationState.size();ic++){
							try {
								scverifcationState.get(ic).join();
							} catch (InterruptedException e) {
								e.printStackTrace();
							}
						}
						
						long fis = System.currentTimeMillis();
						taskOutput.append("      Time of verification SC: "+sdf.format(fis-inis));
						/* ***********FINAL CONCURRENCIA************* */
						
						cleanCheckBoxes();
						frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
						StartEnable();
						
					}
				});
				temp.add(verifallbtn,BorderLayout.SOUTH);				
			}
			contentPane.add(temp);
		}
	}
	private String[] SCUsedToCheckBoxes(){
		String[]llista = new String[cc.getCards().length];
		for(int i=0; i<cc.getCards().length;i++){
			llista[i]= listerminals[cc.getCards()[i]];
		}
		return llista;
		
	}

	
	private int numbMarked(int[] nums) {
		int i=0;
		while(nums[i]!=-1){
			i++;
		}
		return i;
	}
    private String setState(String str){
   	 	message = str;
   	 	return this.message;
    }

	private int[] selectedNumbers(){
		int[] chequedboxes = new int[this.max];
		Arrays.fill(chequedboxes, -1);
		int j=0;
		for(int i=0;i<cc.getCards().length;i++){
			if(this.smartchecks.get(i).isSelected()){
				chequedboxes[j]=i;
				j++;
			}
		}
		
		/*
		 * prova taula escollits
		 */
		for(int i=0;i<chequedboxes.length;i++){
			System.out.println("escollit "+chequedboxes[i]);
		}
		return chequedboxes;
	}
	private int selectedNumber(){
		for(int i=0;i<cc.getCards().length;i++){
			if(this.smartchecks.get(i).isSelected()){
				return i;
			}
		}
		return -1;
	}
	
	 class Task extends SwingWorker<Void, Void> {

		@Override
		public Void doInBackground(){
			String verifss ="";
			WaitDisable();
			frame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
			setProgress(19);
			if(Principal.this.numMax == cc.getNumShares()){
				long tini = System.currentTimeMillis();
				taskOutput.append("VERIFICATION OF THE SC\n");
            	taskOutput.append("------------------------------------------------\n\n");
				for(int i=0; i<cc.getCards().length;i++){
					String sw="";
					String id="";
					try {
						cc.cardConnection(i, cc.getCards()[i]); 
						cc.appletSelectionInitialization(true, i);
						//cc.shareVerification(i);
						taskOutput.append("         Verifying share...\n");
						cc.share1Verification(i);
						id = cc.getResponsesw()[0];
						taskOutput.append("         Verifying share commitment...\n");
						cc.sharecommitmentVerification(i);
						sw = cc.getResponsesw()[0];
						//id = cc.getResponsesw()[1];
						cc.cardDisconnection(i);
					} catch (CardException e) {
						System.out.println(e);
					}
					long tfi = System.currentTimeMillis();
					if(id.equals("9000") && sw.equals("9000")){
					//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" es correcta.");
						verifss="SC verified: \tOk.\n            Time of verification: "+sdf.format(tfi-tini);
					}else if(!(id.equals("9000")) && sw.equals("9000")){
					//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" ha fallat. Error: "+sw);
						verifss="SC verified: \tError: "+id+".\n";
					}else if(!(sw.equals("9000")) && id.equals("9000")){
					//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" ha fallat. Error: "+sw);
						verifss="SC verified: \tError: "+id+".\n";
					}else{
					//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" ha fallat. Error: "+sw);
						verifss="SC verified: \tError: "+id+", and error: "+sw+".\n";
					}
					Principal.this.setState(verifss);
					setProgress(i);
				}
			}else{
				String sw="";
				String id="";
				long tini = System.currentTimeMillis();
				try {
					cc.cardConnection(ids, cc.getCards()[nn]); 
					cc.appletSelectionInitialization(true, ids);
					//cc.shareVerification(ids);
					taskOutput.append("         Verifying share...\n");
					cc.share1Verification(ids);
					id = cc.getResponsesw()[0];
					taskOutput.append("         Verifying share commitment...\n");
					cc.sharecommitmentVerification(ids);
					sw = cc.getResponsesw()[0];
					//id = cc.getResponsesw()[1];
					cc.cardDisconnection(ids);
				} catch (CardException e) {
					e.printStackTrace();
				}
				long tfi = System.currentTimeMillis();
				if(id.equals("9000") && sw.equals("9000")){
					//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" es correcta.");
					verifss="SC verified: \tOk.\n            Time of verification: "+sdf.format(tfi-tini);
				}else if(!(id.equals("9000")) && sw.equals("9000")){
				//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" ha fallat. Error: "+sw);
					verifss="SC verified: \tError: "+id+".\n";
				}else if(!(sw.equals("9000")) && id.equals("9000")){
				//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" ha fallat. Error: "+sw);
					verifss="SC verified: \tError: "+sw+".\n";
				}else{
				//JOptionPane.showMessageDialog(UseCases.this,"Verificacio SC: "+id+" ha fallat. Error: "+sw);
					verifss="SC verified: \tError: "+id+", and error: "+sw+".\n";
				}
				Principal.this.setState(verifss);
				setProgress(nn);
			}
			return null;
		}
		@Override
        public void done() {
			//Waiting.this.
			Toolkit.getDefaultToolkit().beep();
            setCursor(null); //turn off the wait cursor
            frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            StartEnable();
            //taskOutput.append("Fi!\n");
		}
	 }

	 class Taskencrypt extends SwingWorker<Void, Void> {
		@Override
		public Void doInBackground(){
			WaitDisable();
			frame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
			missatgeteclat = jtxt.getText();
			if(missatgeteclat.equals("")){
				JOptionPane.showMessageDialog(Principal.this, "Firstly generate the message");
			}else{
				//String str ="";
				long ini = System.currentTimeMillis();		
				cc.createMessageBox(missatgeteclat);
				if(cc.getM().bitLength()<cc.getPbitLength()){
					//cc.createMessageBox(missatgeteclat);
					//str = cc.getMtoString();
					//taskOutput.append("\t\t   OK\n");
					cc.createMessageBox(missatgeteclat);
					taskOutput.setText("");
					taskOutput.append("MESSAGE ENCRYPTION\n");
					taskOutput.append("------------------------------------------------\n\n");
					taskOutput.append("Encrypting message...");
					try {
						String encrypted =cc.getZ2toString();
						taskOutput.append("\t\t   OK\n");
						taskOutput.append(encrypted+"\n\n");
						long fi = System.currentTimeMillis();
						taskOutput.append("      Time of encryption: "+sdf.format(fi-ini));
						btntally.setEnabled(true);
					} catch (CardException e) {
						System.out.println(e);
					}
				}else{
					taskOutput.setText("");
					jtxt.setText("");
					JOptionPane.showMessageDialog(Principal.this, "Message too longer");
				}
				
				
				
				

			}
			return null;
		}
		@Override
        public void done() {
			Toolkit.getDefaultToolkit().beep();
            setCursor(null); //turn off the wait cursor
            frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            StartEnable();
		}
	 }
	 
	 class Taskdecrypt extends SwingWorker<Void, Void> {
			@Override
			public Void doInBackground(){
				WaitDisable();
				frame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
				try {
					long ini = System.currentTimeMillis();
					int[] ids = Principal.this.selectedNumbers();
					int number=Principal.this.numbMarked(ids);
					if(number < cc.getTHRESHOLD()){
						//JOptionPane.showMessageDialog(ParaProvar.this, "Choose "+cc.getTHRESHOLD()+" o more SC");
						
						for(int i=0; i<cc.getTHRESHOLD();i++){
							smartchecks.get(i).setSelected(true);
						}
						ids = Principal.this.selectedNumbers();
						number=Principal.this.numbMarked(ids);
						taskOutput.setText("");
					}
					
						Integer[] newArray = new Integer[number];
						int i =0;
						while (i<ids.length && ids[i]!=-1) {
							newArray[i] = Integer.valueOf(ids[i]);
							i++;
						}
						for(int ix=0; ix<newArray.length;ix++){
							System.out.println(newArray[ix]);
						}						
						taskOutput.setText("");
						taskOutput.append("DECRYPTION MESSAGE\n");
						taskOutput.append("------------------------------------------------\n\n");
						taskOutput.append("Decrypting message...");
						cc.useTally(newArray);
						taskOutput.append("\n\n    Partial decrypts:");
						
						
						for (int irets=0;irets<cc.getPartialreturns().size();irets++){
							taskOutput.append("\n      "+(irets+1)+". "+cc.getPartialreturns().get(irets));
						}
						String sw =cc.getResponsesw()[0];
						if(sw.equals("9000")){
							taskOutput.append("\n      Message decrypted...\t\t   OK\n");
						}else{
							taskOutput.append("\n      Message decrypted...\t\t   ERROR: "+sw+"\n");
						}
						//taskOutput.append("\nExpected message:  "+cc.getMtoString());
						//taskOutput.append("\nReturned message: "+cc.getDECtoString());
	

						if(cc.getMtoString().equals(cc.getDECtoString())){
							if(missatgeteclat.isEmpty()){
								taskOutput.append("\n      Expected message:  "+cc.getMtoString());
								taskOutput.append("\n      Returned message: "+cc.getDECtoString());
							}else{
								taskOutput.append("\n      Expected message:  "+missatgeteclat);
								taskOutput.append("\n      Returned message: "+missatgeteclat);
							}
							taskOutput.append("\n\n      Succesfully decryption");
						}else{
							/*if(missatgeteclat.isEmpty()){
								taskOutput.append("\nExpected message:  "+cc.getMtoString());
								taskOutput.append("\nReturned message: "+cc.getDECtoString());
							}else{
								taskOutput.append("\nExpected message:  "+missatgeteclat);
								taskOutput.append("\nReturned message: "+missatgeteclat);
							}*/
							taskOutput.append("\n\n      Unsuccesfully decryption");
						}
						long fi = System.currentTimeMillis();
						taskOutput.append("\n\n      Time of decryption: "+sdf.format(fi-ini));
					
				} catch (CardException e) {
					System.out.println(e);
				}
				return null;
			}
			@Override
	        public void done() {
				Toolkit.getDefaultToolkit().beep();
	            setCursor(null); //turn off the wait cursor
	            frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
	            StartEnable();
	            cleanCheckBoxes();
	            jtxt.setText("");
			}
		 }
	 
	 
	 class TaskencryptSim extends SwingWorker<Void, Void> {
			@Override
			public Void doInBackground(){
				WaitDisable();
				frame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
				long inii= System.currentTimeMillis();
				try{
					int np1= (Integer)spP1.getValue();
					int np2= (Integer)spP2.getValue();
					int np3= (Integer)spP3.getValue();
					System.out.println("\n------------------------\n"+np1+","+np2+","+np3);
					taskOutput.setText("");
					//taskOutput.append("0. Message...");
					//taskOutput.append("\n   "+cc.getMtoString()+"\n");
					taskOutput.append("1. Encrypting party vots...");
					for(int i=0; i<np1;i++){
						BigInteger[] n=null;
						if(i==0){
							n =cc.Z_Encrypt(true,primers.get(0).toString());
						}else{
							n =cc.Z_Encrypt(false,primers.get(0).toString());
						}
						//taskOutput.append("\n   "+cc.byteArrayTohexString(n[1].toByteArray()));
						taskOutput.append("\n   vote "+(i+1)+": "+cc.byteArrayTohexString(n[0].toByteArray()));
						//taskOutput.append("\n   "+cc.byteArrayTohexString(n[1].toByteArray()));
					}
					taskOutput.append("\n\n   y1total:"+cc.getY1total());
					taskOutput.append("\n   y2total:"+cc.getY2total());
					taskOutput.append("\n\t\t      \n\n");
					taskOutput.append("2. Encrypting party vots...");
					for(int i=0; i<np2;i++){
						BigInteger[] n= cc.Z_Encrypt(false,primers.get(1).toString());
						taskOutput.append("\n   vote "+(i+1)+": "+cc.byteArrayTohexString(n[0].toByteArray()));
						
					}
					taskOutput.append("\n\n   y1total:"+cc.getY1total());
					taskOutput.append("\n   y2total:"+cc.getY2total());
					taskOutput.append("\n\t\t      \n\n");
					taskOutput.append("3. Encrypting party vots...");
					for(int i=0; i<np3;i++){
						BigInteger[] n=cc.Z_Encrypt(false,primers.get(2).toString());
						taskOutput.append("\n   vote "+(i+1)+": "+cc.byteArrayTohexString(n[0].toByteArray()));
					}
					taskOutput.append("\n\n   y1total:"+cc.getY1total());
					taskOutput.append("\n   y2total:"+cc.getY2total());
					taskOutput.append("\n\t\t      \n\n");
					btnRecompte.setEnabled(true);
					long fii = System.currentTimeMillis();
					taskOutput.append("   Time of encrypting parties votes: "+sdf.format(fii-inii));
				}catch(NumberFormatException e){
					System.out.println(e);
					spP1.setValue(1);
					spP2.setValue(1);
					spP3.setValue(1);
				} catch (CardException e) {
					e.printStackTrace();
				}
				frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
				StartEnable();
			
				return null;
			}
			@Override
	        public void done() {
				Toolkit.getDefaultToolkit().beep();
	            setCursor(null); //turn off the wait cursor
	            frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
	            StartEnable();
	            cleanCheckBoxes();
	            jtxt.setText("");
			}
		 }
	 class TaskdecryptSim extends SwingWorker<Void, Void> {
			@Override
			public Void doInBackground(){
				long inii= System.currentTimeMillis();
				int[] ids = Principal.this.selectedNumbers();
				int number=Principal.this.numbMarked(ids);
				if(number < cc.getTHRESHOLD()){
					//JOptionPane.showMessageDialog(ParaProvar.this, "Choose "+cc.getTHRESHOLD()+" o more SC");
					for(int i=0; i<cc.getTHRESHOLD();i++){
						smartchecks.get(i).setSelected(true);
					}
					ids = Principal.this.selectedNumbers();
					number=Principal.this.numbMarked(ids);
					taskOutput.setText("");
				}
				WaitDisable();
				frame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
				taskOutput.setText("");
				taskOutput.append("Decrypting party vots...");
				Integer[] newArray = new Integer[number];
				int in =0;
				System.out.println("MIDA DELS PRIMERS: "+primers.size());
				System.out.println("newARRAY: "+newArray.length);
				while (in<ids.length && ids[in]!=-1) {
					newArray[in] = Integer.valueOf(ids[in]);
					in++;
				}
				for(int ix=0; ix<newArray.length;ix++){
					System.out.println(newArray[ix]);
				}	
				
				ArrayList<Integer> nvotespartys=null;
				try {
					nvotespartys = cc.Z_Decrypt(primers, newArray);
				} catch (CardException e) {
					e.printStackTrace();
				}
				taskOutput.append("\t\t      OK\n");
				taskOutput.append("\n______________________________________________\n");
				for(int i=0; i<nvotespartys.size();i++)	{
					taskOutput.append("\n       Party "+(i+1)+": "+nvotespartys.get(i)+" votes");
				}
				taskOutput.append("\n______________________________________________\n");
				long fii = System.currentTimeMillis();
				taskOutput.append("       \n\nTime of decrypting parties votes: "+sdf.format(fii-inii));
				frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
				StartEnable();
				return null;
			}
			@Override
	        public void done() {
				Toolkit.getDefaultToolkit().beep();
	            setCursor(null); //turn off the wait cursor
	            frame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
	            StartEnable();
	            cleanCheckBoxes();
	            jtxt.setText("");
			}
		 }
}
