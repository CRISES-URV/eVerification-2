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
 * Frame to the part of distribution
 * 
 * @author Roger Jardí Cedó {@link roger.jardi@urv.cat} & Vicenç Creus Garcia {@link vicens.creus@urv.cat}
 */
public class WaitDistribution extends JFrame implements PropertyChangeListener{
	private static final long serialVersionUID = 1L;
	private Task task;
    private JTextArea taskOutput;
    private JProgressBar progressBar;
    private static CardClient cc;
    private static double  scpercent;
    private static SimpleDateFormat sdf;
    private static String data, datatotal;
    private double incpercent;
    private String message;
    //private String message2;
    private int numCard = -1;
    private JButton seguent;
    private String[] temps = new String[3];
    private JFrame frame;
    private JPanel panel_1;
    private long inici, figen;
	/**
	 * Launch the application.
	 * @throws CardException 
	 */
	/*public static void main(String[] args) { 
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					WaitWindow frame = new WaitWindow();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}*/
    /**
     * Falta agafar els numshares autentics de cc.getNumShares()
     * @throws CardException
     */
    
    /*public static void main(String[] args) {
        //Schedule a job for the event-dispatching thread:
        //creating and showing this application's GUI.
        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try { 
					createAndShowGUI();
					//sdf = ini_generator();
				} catch (CardException e) {
					e.printStackTrace();
				}
            }
        });
    }*/

	/**
	 * Create the frame.
	 * @throws CardException 
	 */
	public WaitDistribution(CardClient ccj, long inici, long fi) throws CardException {
	    //Create the demo's UI
		cc=ccj;
		this.inici=inici;
		figen = fi;
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
        
        seguent = new JButton("Next");
        panel_1.add(seguent);
        seguent.setMinimumSize(new Dimension(44, 23));
        seguent.setMaximumSize(new Dimension(46, 23));
        seguent.setVisible(false);
        seguent.setIcon(arrow);
        seguent.setSize(15, 10);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        
        frame.setTitle("Distribution: ("+cc.getTHRESHOLD()+","+cc.getNumShares()+") - ElGamal Threshold Scheme ["+cc.getPbitLength()+" bits]");
       
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
            //inicialitza el generador
            if(progress==1){
            	taskOutput.append("DISTRIBUTION OF SHARES\n");
            	taskOutput.append("-------------------------------------------------\n\n");
            }else if(progress == 100){
            	//System.out.println("hola2");
            	progressBar.setValue(progress);
            	if(cc.getResponsesw()[0].equals("9000")){
            		taskOutput.append("\t\tOK  "+message);
            	}else{
            		taskOutput.append("\t\tError: "+cc.getResponsesw()[0]);
            	}
            	temps[1]=data;
            	temps[2]=datatotal;
            }else{
            	progressBar.setValue(progress);
            	if(numCard!=Integer.parseInt(cc.getResponsesw()[1]) && Integer.parseInt(cc.getResponsesw()[1])!=0){
            		if(Integer.parseInt(cc.getResponsesw()[1])!=1){
            			taskOutput.append("      \n------------------------------------------------------------------\n");
            		}
            		taskOutput.append("      Smart Card "+cc.getResponsesw()[1]+"\n");
            		taskOutput.append("        1. Inicializating the applet...                   ");
            		numCard = Integer.parseInt(cc.getResponsesw()[1]);
            	}
            	if(cc.getResponsesw()[0].equals("9000")){
            		//taskOutput.append("\t\t\tOK\n ");
            		taskOutput.append("\t\tOK  "+this.message);
            	}else{
            		//taskOutput.append(String.format("Completat %d%%.\n", task.getProgress()));
            		taskOutput.append("\t\tError: "+cc.getResponsesw()[0]+"        "+this.message);
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
        	long fi = System.currentTimeMillis();
            scpercent = 100/(WaitDistribution.cc.getNumShares()-1);
            System.out.println("SCPERCENMT:"+scpercent+", INCPERCENT: "+incpercent);
            double sumpercent = 0.0;
            //Initialize progress property.
            setProgress(0);

			
     		incpercent = scpercent/5; //because there are 4 operations per SC
     		setProgress(1);
     		try {
	    		for (int i=1; i<cc.getNumShares(); i++){
	    			sumpercent = scpercent*(i-1);
	    			long ini =System.currentTimeMillis();
	    			cc.cardConnection(i, cc.getCards()[i]);
	    			cc.appletSelectionInitialization(false, i); //true = is initialized
	    			long fis =System.currentTimeMillis();
	    			setState("("+sdf.format(fis-ini)+")\n        2. Inicialitzating ElGamal...             ");
	    			setProgress((int)(sumpercent+incpercent));
	    			System.out.println("iniapplet"+(sumpercent+incpercent));
	    			ini =System.currentTimeMillis();
	    			cc.elGamalInitialization(false, i); //true = is generator
	    			fis =System.currentTimeMillis();
	    			setState("("+sdf.format(fis-ini)+")\n        3. Getting share from generator SC...     ");
	    			setProgress((int)(sumpercent+incpercent*2));
	    			
	    			ini =System.currentTimeMillis();
	    			cc.thresholdParticularParametersBroaCasting(0,i);
	    			fis =System.currentTimeMillis();
	    			setState("("+sdf.format(fis-ini)+")\n        4. Sending share to SC "+i+"...            ");
	    			
	    			setProgress((int)(sumpercent+incpercent*3));
	    			ini =System.currentTimeMillis();
	    			cc.thresholdParametersReceiving(i);
	    			fis =System.currentTimeMillis();
	    			setState("("+sdf.format(fis-ini)+")\n        5. Verifying shares...                      ");
	    			setProgress((int)(sumpercent+incpercent*4));
	    			ini =System.currentTimeMillis();
	    			cc.shareVerification(i);
	    			fis =System.currentTimeMillis();
	    			if(i+1!=cc.getNumShares()){
	    				setState("("+sdf.format(fis-ini)+")\n ");
	    				setProgress((int)(sumpercent+incpercent*5));
	    			}else{
	    				setState("("+sdf.format(fis-ini)+")\n ");
	    			}
	    			cc.cardDisconnection(i);
	    		}
	    		
	    		cc.cardDisconnection(0);
	    		long ini2 = System.currentTimeMillis();
	    		data = sdf.format(ini2-fi);
	    		//datatotal = sdf.format(ini2-inici);
	    		datatotal  = sdf.format((figen-inici)+(ini2-fi));
    			setProgress(100);
	    		
     		} catch (CardException e) {
    			System.out.println(e);
    		}
            return null;
        }

        /*
         * Executed in event dispatching thread
         */
        @Override
        public void done() {
            Toolkit.getDefaultToolkit().beep();
            frame.setCursor(null); //turn off the wait cursor
            //taskOutput.append("Fi!\n");
            
            taskOutput.append("\n\n___________________________\n\n    Time of distribution: "+temps[1]+"\n    Total time: "+datatotal+"\n__________________________\n");
            
            seguent.setVisible(true);
            seguent.addActionListener(new ActionListener(){
				@Override
				public void actionPerformed(ActionEvent arg0) {
					try {
						WaitDistribution.this.setVisible(false);
						frame.dispose();
						new Principal(cc);
						//new UseCases(cc);
					} catch (CardException e) {
						System.out.println(e);
					}
				}
            	
            });
            
        }
    }

}
