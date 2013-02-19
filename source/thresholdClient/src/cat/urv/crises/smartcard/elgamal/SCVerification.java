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
import java.util.ArrayList;
import javax.smartcardio.CardException;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/**
 * Class to make a concurrent verification of the SC.
 * 
 * @author Roger Jardí Cedó {@link roger.jardi@urv.cat} & Vicenç Creus Garcia {@link vicens.creus@urv.cat}
 */
public class SCVerification extends Thread{

	private int id, pos;
	private CardClient cc;
    private JTextArea taskOutput;
    private JButton genera, btntally, btnXifra, btnSimularVoting, verifallbtn;
	private ArrayList<JCheckBox> smartchecks;
	private ArrayList<JButton> verifsbtns;
    private JTextField jtxt;
    /**
     * Constructor for initialization the parameters of the SC to verify the share and the share commitment
     * @param cac reference to a CardClient object to do the operations in the SC
     * @param ide identifier of the SC
     * @param posi position in the list
     * @param task graphic interface
     * @param gener graphic interface
     * @param btntaly graphic interface
     * @param btnSimular graphic interface
     * @param btnXifr graphic interface
     * @param verallbtn graphic interface
     * @param veribtns graphic interface
     * @param smtchecks graphic interface
     * @param jtt graphic interface
     */
	public SCVerification(CardClient cac,int ide, int posi, JTextArea task, JButton gener, JButton btntaly, JButton btnSimular, JButton btnXifr, JButton verallbtn,  ArrayList<JButton> veribtns, ArrayList<JCheckBox> smtchecks, JTextField jtt){
		super();
		cc=cac;
		id=ide;
		pos=posi;
		taskOutput=task;
		genera = gener;
		btntally = btntaly;
		btnXifra = btnXifr;
		btnSimularVoting= btnSimular;
		verifallbtn= verallbtn;
		verifsbtns= veribtns;
		smartchecks= smtchecks;
		jtxt = jtt;
	}
	public final void run () {
		String retsw="";
		String retid="";
		//long tini=System.currentTimeMillis();
		try {
			WaitDisable();
			cc.cardConnection(id, cc.getCards()[pos]); 
			cc.appletSelectionInitialization(true, id);
			
			taskOutput.append("         Verifying share SC "+id+"...\n");
			cc.share1Verification(id);
			retid = cc.getResponsesw()[0];
			taskOutput.append("         Verifying share commitment SC "+id+"...\n");
			cc.sharecommitmentVerification(id);
			retsw = cc.getResponsesw()[0];
			//id = cc.getResponsesw()[1];
			cc.cardDisconnection(id);
		} catch (CardException e) {
			e.printStackTrace();
		} 
		if(retid.equals("9000") && retsw.equals("9000")){
			taskOutput.append("           SC "+id+" verified: \tOk.\n");
		}else if(!(retid.equals("9000")) && retsw.equals("9000")){
			taskOutput.append("           SC "+id+" verified: \tError: "+retid+".\n");
		}else if(!(retsw.equals("9000")) && retid.equals("9000")){
			taskOutput.append("           SC "+id+" verified: \tError: "+retsw+".\n");
		}else{
			taskOutput.append("           SC "+id+" verified: \tError: "+retid+", and error: "+retsw+".\n");
		}
		StartEnable();
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
}
