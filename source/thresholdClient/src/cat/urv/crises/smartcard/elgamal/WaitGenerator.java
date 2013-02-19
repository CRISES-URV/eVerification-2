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
 * The Beta version of this code has been implemented by Jordi Castell�, Vicen� Creus, 
 * Roger Jard� and Jordi Pujol ([jordi.castella,vicenc.creus,roger.jardi,jordi.pujol]@urv.cat).
 * 
 */
import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Toolkit;
import javax.smartcardio.CardException;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.text.SimpleDateFormat;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.border.EmptyBorder;
import javax.swing.JButton;
/**
 * Frame to the part of generation
 *
 * @author Roger Jard� Ced� {@link roger.jardi@urv.cat} & Vicen� Creus Garcia {@link vicens.creus@urv.cat}
 */
public class WaitGenerator extends JFrame implements PropertyChangeListener{
	private static final long serialVersionUID = 1L;
	private Task task;
	private JTextArea taskOutput;
	private JProgressBar progressBar;
	private static CardClient cc;
	private static SimpleDateFormat sdf;
	private static String data;
	private double incpercent;
	private String message;
	private JButton seguent;
	private String[] temps = new String[3];
	private JFrame frame;
	private long ini, fi;
	private JPanel panel_1;
	/**
	 * Create the frame.
	 * @throws CardException 
	 */
	public WaitGenerator(CardClient ccj) throws CardException {
	    //Create the demo's UI
		cc=ccj;
		sdf  = new SimpleDateFormat("mm:ss.SSS");
	        progressBar = new JProgressBar(0, 100);
	        progressBar.setBorder(new EmptyBorder(0, 0, 10, 0));
	        progressBar.setValue(0);
	        progressBar.setStringPainted(true);
	
	        taskOutput = new JTextArea(20, 20);
	        taskOutput.setMargin(new Insets(5,5,5,5));
	        taskOutput.setEditable(false);
	        
	        JPanel panel = new JPanel(new BorderLayout());
	        panel.setBorder(new EmptyBorder(5, 10, 0, 10));
	        panel.add(progressBar, BorderLayout.NORTH);
	        panel.add(new JScrollPane(taskOutput), BorderLayout.CENTER);
	                
	        frame = new JFrame();
	        frame.getContentPane().add(panel, BorderLayout.PAGE_START);
	        ImageIcon arrow = new ImageIcon("images/arrow.png");
	        
	        panel_1 = new JPanel();
	        panel_1.setBorder(new EmptyBorder(0, 0, 0, 4));
	        frame.getContentPane().add(panel_1, BorderLayout.EAST);
	        
	        seguent = new JButton("Distribution");
	        panel_1.add(seguent);
	        seguent.setMinimumSize(new Dimension(44, 23));
	        seguent.setMaximumSize(new Dimension(46, 23));
	        seguent.setVisible(false);
	        seguent.setIcon(arrow);
	        seguent.setSize(15, 10);
	        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	        
	        frame.setTitle("Generation: ("+cc.getTHRESHOLD()+","+cc.getNumShares()+") - ElGamal Threshold Scheme ["+cc.getPbitLength()+" bits]");
	        //Display the window.
	        frame.setSize(540,450);
	        Dimension pantalla = Toolkit.getDefaultToolkit().getScreenSize();
	        Dimension ventana = frame.getSize();
	        frame.setLocation((pantalla.width - ventana.width) / 2,(pantalla.height - ventana.height) / 2);
	        frame.setVisible(true);
	        
	        frame.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		task = new Task();
		task.addPropertyChangeListener(this);
		task.execute();
	}
	
	public void propertyChange(PropertyChangeEvent evt) {
		if ("progress" == evt.getPropertyName()) {
			int progress = (Integer) evt.getNewValue();
			//initialize the generator SC
			if(progress==1){
			setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			taskOutput.append("INICIALIZATION OF THE GENERATOR\n");
			taskOutput.append("------------------------------------------------\n\n");
			taskOutput.append("   Smart Card 0, generator\n");
			taskOutput.append("        1. Inicializating the applet...                ");
			progressBar.setValue(1);
            	}else if(progress == 100){
            		progressBar.setValue(progress);
            		if(cc.getResponsesw()[0].equals("9000")){
            			taskOutput.append("\t\tOK  "+this.message);
            		}else{
            			taskOutput.append("\t\tError: "+cc.getResponsesw()[0]);
            		}
            		temps[0]=data;
            	}else{
            		progressBar.setValue(progress);
            		if(cc.getResponsesw()[0].equals("9000")){
	            		taskOutput.append("\t\tOK  "+this.message);
        	    	}else{
            			taskOutput.append("\t\tError: "+cc.getResponsesw()[0]+"\n        "+this.message);
            		}	
            }
        }
    }
     private String setState(String str){
    	 message = str;
    	 return this.message;
     }
     
    class Task extends SwingWorker<Void, Void> {
        /*
         * Main task. Executed in background thread.
         */
        @Override
        public Void doInBackground() {
            incpercent = 100/5;            
            //Initialize progress property.
            setProgress(0);
            ini = System.currentTimeMillis();
   
    		try {
    			//******Generator SC******
    			setProgress(1);
    			long ini =System.currentTimeMillis();
    			cc.cardConnection(0, cc.getCards()[0]);
    			cc.appletSelectionInitialization(false, 0);
    			long fi =System.currentTimeMillis();
    			WaitGenerator.this.setState("("+sdf.format(fi-ini)+")\n        2. Inicializating ElGamal...                  ");
    			setProgress((int)incpercent);
    			ini =System.currentTimeMillis();
    			cc.elGamalInitialization(true, 0);
    			fi =System.currentTimeMillis();
    			WaitGenerator.this.setState("("+sdf.format(fi-ini)+")\n        3. Generating shares...                       ");
    			setProgress((int)incpercent*2);
    			ini =System.currentTimeMillis();
    			cc.thresholdSchemeGeneration(0);
    			fi =System.currentTimeMillis();
    			WaitGenerator.this.setState("("+sdf.format(fi-ini)+")\n        4. Getting coefs. commitments and pk...    ");
    			setProgress((int)incpercent*3);
    			ini =System.currentTimeMillis();
    			cc.thresholdCommonParametersBroaCasting(0);
    			fi =System.currentTimeMillis();
    			WaitGenerator.this.setState("("+sdf.format(fi-ini)+")\n        5. Verifying share...                          ");
    			setProgress((int)incpercent*4);
    			ini =System.currentTimeMillis();
    			cc.shareVerification(0); //it can be done here or before the tally process
    			fi =System.currentTimeMillis();
    			WaitGenerator.this.setState("("+sdf.format(fi-ini)+")");
    			setProgress((int)100);
    			
    		} catch (CardException e) {
    			System.out.println(e);
    		}
    		
     		fi = System.currentTimeMillis();
     		data = sdf.format(fi-ini);
            return null;
        }

        /*
         * Executed in event dispatching thread
         */ 
        @Override
        public void done() {
            Toolkit.getDefaultToolkit().beep();
            frame.setCursor(null); //turn off the wait cursor
            taskOutput.append("\n\n___________________________\n\n    Time of generation: "+temps[0]+"\n__________________________\n");
            seguent.setVisible(true);
            seguent.addActionListener(new ActionListener(){
		@Override
		public void actionPerformed(ActionEvent arg0) {
			try {
				WaitGenerator.this.setVisible(false);
				frame.dispose();
				new WaitDistribution(cc, ini, fi);						
			} catch (CardException e) {
				System.out.println(e);
			}
		}
            });       
        }
    }
}
