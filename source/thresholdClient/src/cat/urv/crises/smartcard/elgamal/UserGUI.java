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
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Toolkit;

import java.awt.ItemSelectable;
import java.util.ArrayList;
import java.util.Arrays;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JLabel;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.FlowLayout;
import javax.swing.JComboBox;
import java.awt.Component;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.BoxLayout;

/**
 * Interface that permit to choose the options for create the threshold scheme
 * 
 * @author Roger Jardí Cedó {@link roger.jardi@urv.cat} & Vicenç Creus Garcia {@link vicens.creus@urv.cat}
 *
 */
public class UserGUI extends JFrame {
	private static final long serialVersionUID = 1L;
	private final int max=10;
	private CardTerminal[] terminal = new CardTerminal[max];
	private List<CardTerminal> terminals;
	private TerminalFactory factory;
	private JPanel contentPane;
	private String escollit="";
	private String[] listerminals=null;
	private String[] listerminals2=null;
	private String[] listerminals3=null;
	private String[] listerminals4=null;
	private ArrayList<JCheckBox> smartchecks;
	private JPanel panel_checks; 
	public static void main(final String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					UserGUI frame = new UserGUI();
					frame.setVisible(true);
				} catch (Exception e) {
					System.out.println(e);
				}
			}
		});
	}

	/**
	 * Create the frame.
	 * @throws CardException 
	 */
	public UserGUI() throws CardException {
		setResizable(false);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		contentPane =  new JPanel();
		contentPane.setBorder(new EmptyBorder(12, 12, 5, 12));
		setContentPane(contentPane);
		contentPane.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		String[] mides = {"512", "768", "1024", "1536","2048"};
		final String[] numsc = {"3", "4","5"};
		String[] numllin = {"2", "3", "4","5"};
		JLabel lblmida = new JLabel("Enter the key size:                                           ");
		contentPane.add(lblmida);
		
		//numero de terminals conectats
		for(int i=0;i<max;i++){
			if (terminal[i] == null){
				factory = TerminalFactory.getDefault(); //uses SunPCSC; the unique available to interact with PC/SC stack.
				terminals = factory.terminals().list();
			}
		}
		listerminals= new String[terminals.size()+1];
		listerminals2= new String[terminals.size()];
		listerminals3= new String[terminals.size()+1];
		this.listerminals[0]="...";
		this.listerminals3[0]="..."; 
		int j = 0;
		for (CardTerminal t:terminals){
			listerminals[j+1]=t.getName();
			if(t.isCardPresent()){
				listerminals2[j]=t.getName()+"\t\t\t         present";
				listerminals3[j+1]=t.getName();
			}else{
				listerminals2[j]=t.getName()+"\t\t\t         no present";
				listerminals3[j+1]="-1";
			}
			j++;
		}
		ArrayList<String> llistafinal = new ArrayList<String>(); 
		llistafinal.add("...");
		for(int i=0;i<listerminals3.length;i++){
			if(!(listerminals3[i].equals("-1"))&& !(listerminals3[i].equals("..."))){
				llistafinal.add(listerminals3[i]);
			}
		}
		listerminals4= llistafinal.toArray(new String[llistafinal.size()]);
		final JComboBox combomides = new JComboBox(mides);
		contentPane.add(combomides);
		
		JLabel lblsc = new JLabel("Enter the number of SC:                                 ");
		lblsc.setAlignmentX(Component.RIGHT_ALIGNMENT);
		contentPane.add(lblsc);
		final JComboBox combosc = new JComboBox(numsc);
		combosc.setSelectedItem(numsc[2]);
		contentPane.add(combosc);
		JLabel lbllindar = new JLabel("Enter the threshold:                                         ");
		contentPane.add(lbllindar);
		final JComboBox combollind = new JComboBox(numllin);
		combollind.setSelectedItem(numllin[1]);
		contentPane.add(combollind);
		
		combosc.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				combollind.removeAllItems();
				for(int i=2;i<=Integer.parseInt((String)combosc.getSelectedItem());i++){
					combollind.addItem(Integer.toString(i));
				}
			}
		});
		
		
		JLabel lblSmart = new JLabel("Enter the generator SC:                                              ");
		contentPane.add(lblSmart);
		final JComboBox comboternms = new JComboBox(listerminals4);
		contentPane.add(comboternms);
		comboternms.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
		        ItemSelectable is = (ItemSelectable)actionEvent.getSource();
		        String str =selectedString(is);
		        int i=0;
		        boolean trobat =false;
		        while( !trobat && i<listerminals2.length){
		        	if(listerminals2[i].contains(str) && listerminals2[i].contains("no present")){
		        		JOptionPane.showMessageDialog(UserGUI.this, "Choose a reader with a SC inserted.");
		           		trobat =true;
		        	}
		        	i++;
		        	
		        }
		        if (trobat)
		        	UserGUI.this.cleanCheckBoxes();
		        if(!(is.equals("...")) && !trobat){
		        	UserGUI.this.escollit = selectedString(is);
			        UserGUI.this.selectedInList();	
		        }
			}
			
		});
		JLabel lblSmarts = new JLabel("Enter the rest SC to use:                                                ");
		lblSmarts.setBorder(new EmptyBorder(30, 0, 0, 0));
		contentPane.add(lblSmarts);
		
		JLabel header = new JLabel("Smart Cards                                             ");
		header.setBorder(new EmptyBorder(10,10,10,20));
		contentPane.add(header);
		panel_checks = new JPanel();
		contentPane.add(panel_checks);
		panel_checks.setLayout(new BoxLayout(panel_checks, BoxLayout.Y_AXIS));
		this.smartchecks = new ArrayList<JCheckBox>();
		for(int i=0;i<listerminals2.length;i++){
			JCheckBox check =new JCheckBox(listerminals2[i]);
			//check.setBorder(new EmptyBorder(9,15,0,0));
			
			this.smartchecks.add(check);
			//contentPane.add(check);
			if(check.getText().contains("no present")==false){
				check.setText(check.getText().substring(0, check.getText().length()-7));
				panel_checks.add(check);
			}
			//panel_checks.add();
			final int n=i;
			this.smartchecks.get(i).addActionListener(new ActionListener(){
				@Override
				public void actionPerformed(ActionEvent arg0) {
					if(UserGUI.this.smartchecks.get(n).isSelected() && UserGUI.this.smartchecks.get(n).getText().contains("no present")){
						JOptionPane.showMessageDialog(UserGUI.this, "Choose a reader with a SC inserted.");
						UserGUI.this.smartchecks.get(n).setSelected(false);
					}
				}
				
			});
		}
		
		JPanel panel_1 = new JPanel();
		FlowLayout flowLayout_1 = (FlowLayout) panel_1.getLayout();
		flowLayout_1.setAlignment(FlowLayout.RIGHT);
		contentPane.add(panel_1);
		
		JLabel label = new JLabel("\r\n                                                                             ");
		panel_1.add(label);
		
		JButton btnact = new JButton("Update");
		panel_1.add(btnact);
		btnact.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				try {
					UserGUI.this.updateSC();
					UserGUI.this.panel_checks.removeAll();
					UserGUI.this.panel_checks.setVisible(false);
					
					System.out.println(UserGUI.this.smartchecks.size());
					UserGUI.this.smartchecks = new ArrayList<JCheckBox>();
					for(int i=0;i<listerminals2.length;i++){
						JCheckBox check =new JCheckBox(listerminals2[i]);
						UserGUI.this.smartchecks.add(check);
						
						//contentPane.add(check);
						//panel_checks.add(check);
						//contentPane.add(check);
						if(check.getText().contains("no present")==false){
							check.setText(check.getText().substring(0, check.getText().length()-7));
							panel_checks.add(check);
						}
						final int n=i;
						UserGUI.this.smartchecks.get(i).addActionListener(new ActionListener(){
							@Override
							public void actionPerformed(ActionEvent arg0) {
								if(UserGUI.this.smartchecks.get(n).isSelected() && UserGUI.this.smartchecks.get(n).getText().contains("no present")){
									JOptionPane.showMessageDialog(UserGUI.this, "Choose a reader with a SC inserted.");
									UserGUI.this.smartchecks.get(n).setSelected(false);
								}
							}
							
						});
					}
					
					UserGUI.this.panel_checks.setVisible(true);
					
					
					
					//comboBox
					comboternms.removeAllItems();
					for(int i=0;i<listerminals4.length;i++){
						comboternms.addItem(listerminals4[i]);
					}
					
					
				} catch (CardException e) {
					System.out.println(e);
				}
				
			}
			
		});
		JPanel panel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) panel.getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		panel.setAlignmentX(10.0f);
		contentPane.add(panel);
		JLabel omple =new JLabel("\r\n                                                                              ");
		panel.add(omple);
		JButton btnAccepta = new JButton("Accept");
		panel.add(btnAccepta);
		btnAccepta.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				int[] ids =UserGUI.this.selectedNumbers();
				int number=UserGUI.this.numbMarked(ids);
				if(number<Integer.parseInt((String)combosc.getSelectedItem()) && number>0){
					int n=Integer.parseInt((String)combosc.getSelectedItem())-number;
					JOptionPane.showMessageDialog(UserGUI.this, /*"Nomes has introduit "+number+" */"You have to enter "+n+" more SC.");
				}else if(number>Integer.parseInt((String)combosc.getSelectedItem()) && number>0){
					int n=number-Integer.parseInt((String)combosc.getSelectedItem());
					if(n==1){
						JOptionPane.showMessageDialog(UserGUI.this, /*"Has introduit "+number+*/"You have entered "+n+" more SC.");
					}else{
						JOptionPane.showMessageDialog(UserGUI.this, /*"Has introduit "+number+*/"You have entered "+n+" more SC.");
					}
				}else if(ids[0]==-1){
					JOptionPane.showMessageDialog(UserGUI.this, "You do not enter the generator");
				}else if(number>Integer.parseInt((String)combosc.getSelectedItem())){
					JOptionPane.showMessageDialog(UserGUI.this, "You have to enter more than "+number+" SC");
				}else{
					CardClient cc =null;
					try {	
						System.out.println(Integer.parseInt((String)combosc.getSelectedItem())+", "+Integer.parseInt((String)combollind.getSelectedItem())+", "+Short.parseShort((String)combomides.getSelectedItem()));
						cc = new CardClient(Integer.parseInt((String)combosc.getSelectedItem()),Integer.parseInt((String)combollind.getSelectedItem()),Short.parseShort((String)combomides.getSelectedItem()),Arrays.copyOf(ids, Integer.parseInt((String)combosc.getSelectedItem())));
						UserGUI.this.setVisible(false);						
						new WaitGenerator(cc);
					} catch (CardException e) {
						System.out.println(e);
					}
				}
				
			}
			
		});
		JButton btnCancela = new JButton("Cancel");
		panel.add(btnCancela);
		btnCancela.addActionListener(new ActionListener(){

			@Override
			public void actionPerformed(ActionEvent arg0) {
				combomides.setSelectedIndex(0);
				combollind.setSelectedIndex(0);
				combosc.setSelectedIndex(3);
				comboternms.setSelectedIndex(0);
				UserGUI.this.cleanCheckBoxes();
			}
			
		});
		this.setSize(500,600);
		setTitle("ElGamal Threshold Scheme");
        Dimension pantalla = Toolkit.getDefaultToolkit().getScreenSize();
        Dimension ventana = getSize();
        setLocation((pantalla.width - ventana.width) / 2,(pantalla.height - ventana.height) / 2);
	}
	protected int numbMarked(int[] nums) {
		int n=0;
		if(!(this.escollit.equals("..."))){
			int i=0;
			while(nums[i]!=-1){
				n++;
				i++;
			}
		}else{
			return -1;
		}
		return n;
	}
	private  void updateSC() throws CardException{
		//numero de terminals conectats
		for(int i=0;i<max;i++){
			if (terminal[i] == null){
				factory = TerminalFactory.getDefault(); //uses SunPCSC; the unique available to interact with PC/SC stack.
				terminals = factory.terminals().list();
			}
		}
		listerminals= new String[terminals.size()+1];
		listerminals2= new String[terminals.size()];
		this.listerminals[0]="..."; 
		int j = 0;
		for (CardTerminal t:terminals){
			listerminals[j+1]=t.getName();
			if(t.isCardPresent()){
				listerminals2[j]=t.getName()+"\t\t\t         present";
				listerminals3[j+1]=t.getName();
			}else{
				listerminals2[j]=t.getName()+"\t\t\t         no present";
				listerminals3[j+1]="-1";
			}
			j++;
		}
		listerminals4= new String[terminals.size()+1];
		listerminals4[0]="..."; 
		int ix=1;
		for(int i=0;i<listerminals3.length;i++){
			if(!(listerminals3[i].equals("-1"))&& !(listerminals3[i].equals("..."))){
				listerminals4[ix]=listerminals3[i];
				ix++;
			}
		}
	}
	private String selectedString(ItemSelectable is) {
		Object selected[] = is.getSelectedObjects();
		return ((selected.length == 0) ? "null" : (String)selected[0]);
	}
	private void selectedInList(){
		//borrar marcatge anterior
		cleanCheckBoxes();
		for(int i=1;i<this.listerminals.length;i++){
			if(!(escollit.equals("...")) && escollit.equals(this.listerminals[i])){
				this.smartchecks.get(i-1).setSelected(true);
				for(int ix=0;ix<smartchecks.size();ix++){
					smartchecks.get(ix).setEnabled(true);
				}
				smartchecks.get(i-1).setEnabled(false);
			}
		}

	}
	private void cleanCheckBoxes(){
		for(int i=0;i<this.smartchecks.size();i++){
			this.smartchecks.get(i).setSelected(false);
		}
	}
	private int[] selectedNumbers(){
		int[] chequedboxes = new int[this.max];
		Arrays.fill(chequedboxes, -1);
		int j=1;
		for(int i=1;i<this.listerminals.length;i++){
			if(escollit.equals(this.listerminals[i])){
				this.smartchecks.get(i-1).setSelected(true);
				chequedboxes[0]=i-1;
			}else if(this.smartchecks.get(i-1).isSelected()){
				chequedboxes[j]=i-1;
				j++;
			}
			
		}
		return chequedboxes;
	}
}
