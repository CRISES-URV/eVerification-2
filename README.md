<a href="http://crises-deim.urv.cat/everification2/" target="_blank"><img src="https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoeverification2.png" />

eVeriﬁcation2 TSI-020100-2011-39 is a research project leaded by Scytl Secure Electronic Voting S.A.,
with the collaboration of CRISES research group from Universitat Rovira i Virgili, and supported by 
the Spanish Ministry of Industry, Commerce and Tourism (through the development program AVANZA I+D).

<a href="https://www.planavanza.es" target="_blank"><img src="https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logo_planAvanza2.png"  width="300" height="150">

<center><table border="0">
<tr><td><a href="http://www.scytl.es" target="_blank"><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoScytl.png border="0"></td>
<td><a href="http://www.urv.cat" target="_blank"><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoURV.png border="0"></td>
<td><a href="http://crises-deim.urv.cat" target="_blank"><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoCrises.png width="140" height="50" border="0"></td></tr>
</table></center>

You can find more information about eVerification2 project in http://crises-deim.urv.cat/everification2

#TTP SmartCard-Based ElGamal Cryptosystem Using Threshold Scheme for Electronic Elections

As a result of this research project, CRISES group has studied the feasibility of developing ElGamal 
cryptosystem and Shamir’s secret sharing scheme into JavaCards, whose API gives no support for it.

In particular, the contributions of our work have been the design and development for JavaCards of
the following building blocks: (i) ElGamal cryptosystem to generate the ElGamal key pair, (ii) Shamir’s 
secret sharing scheme to divide the private key in a set of shares, (iii) secure communication channels 
for the distribution of the shares, and (iv) a decryption function without reconstructing the private key. 
This solution can be useful for a typical e-voting system, speciﬁcally in the voting scheme presented by 
Cramer et al. [<a href="#ref1">1</a>].

You can find more information about these contributions and how it had been desinged and implemented in the 
conference <a href="https://raw.github.com/CRISES-URV/eVerification-2/master/paper.pdf">paper.pdf</a> presented in Foundations & Practice of Security 2011 called: TTP SmartCard-Based ElGamal 
Cryptosystem Using Threshold Scheme for Electronic Elections [<a href="#ref2">2</a>]. In the <a href="https://raw.github.com/CRISES-URV/eVerification-2/master/extendedpaper.pdf">extendedpaper.pdf</a>, you can find a 
description of an execution example.


##Software

This library implements the protocol described in the paper described above and is prepared to execute a 
configurable example with a maximum number of shares (n=5) and a threshold from 2 to the maximum of shares (n).

In addition, it is provide with a GUI that permits execute easily the following functions implemented in the library:
- Generate a set of shares from a SmartCard(SC) according to user configuraction (number of shares, threshold and key size).
- Distribute the generated shares, public key, and other public parameters from that SC to the rest of SCs.
- Verify the received share from each SC. 
- Encrypt a value using the public ElGamal parameters.
- Partial decrypt from each SC.
- Homomorphic Recount (in a voting context) through the aggregation of the set of partial decryptions.

The code is divided in two different parts: thresholdClient and thresholdLib code.
The former part includes the GUI and the code related to manage of the protocol execution as a client. This part has been developed
in Java programming language.
The last part is the applet code placed/installed into each SC, which is written in JavaCard.

<!--TODO: afegir figures esquemes-->

Once the applet has been installed, the user can execute the following utilities:

1. Generation.
    <!--TODO: afegir figures esquemes i output de les apdus de generacio-->
    
2. Distribution between generator smart card and slave or receiver smart card. This step is executed in each receiver smart card.

		1. We have to initialize the applet. In this case, the applet identifier is 3132333433123450.

		2. We have to initialize the ElGamal . For this initialization we generate the following values:
			- p: the APDU used to generate p is: CLA=90, INS=01, P1-P2=00, Lc=20 and data=p. 
			- q: the APDU used to generate q is: CLA=90, INS=11, P1-P2=00, Lc=20 and data=q. 
			- g: the APDU used to generate g is: CLA=90, INS=02, P1-P2=00, Lc=20 and data=g. 

		3. We have to broadcasting the particular parameters of threshold.
			- We have to get share and share commitment from smart card (generator). The APDUs are the following:
				- The APDU used to get share is: CLA=80, INS=19, P1= smart card identifier,P2=00.
				- The APDU used to get share commitment is: CLA=80, INS=1C, P1= smart card identifier, P2=00.

		4. We have to receiving the threshold parameters generated in the generation step. The APDUs are the following:
			- We have to get the value of the threshold and the number of shares. In this case, the APDU is: CLA=80, INS=1e, P1=2-5,P2=3-5
			- We have to save coefficient commitment. In this case, the APDU is: CLA=90, INS=16, P1-P2=00.
			- We have to save the card identifier. In this case, the APDU is: CLA=80, INS=12, P1-P2=00, Lc=01 and data=id_card.
			- We have to save own share. In this case, the APDU is: CLA=90, INS=14, P1-P2=00, Lc=20 and data=share.
			- We have to save own share commitment. In this case, the APDU is: CLA=90, INS=17, P1-P2=00, Lc=20 and data=share commitment.
			- We have to save the public key. In this case, the APDU is: CLA=90, INS=15, P1-P2=00, Lc=20 and data=public key.
			- We have to generate evaluation values. In this case, the APDU is: CLA=80, INS=07, P1-P2=00.

		5. We have to verify share and share commitment.
			- The APDU used to verify share is: CLA=80, INS=A0, P1-P2=00.
			- The APDU used to verify share commitment is: CLA=80, INS=B0, P1-P2=00.


3. Encryption

		1. We have to initialize the applet. In this case the applet identifier is 3132333433123450.
		2. We have to send data to encrypt. In this case, the APDU is: CLA=90, INS=0C, P1-P2=00, Lc=20, Data=message to encrypt.
		3. We have to ask for ElGamal encryption result. In this case, the APDU is: CLA=90, INS=0D, P1-P2=00.


4. Decryption

		1. We have to generate evaluation values and Lagrange coefficients.
		2. We have to initialize the applet. In this case the applet identifier is 3132333433123450.
		3. We have to send Lagrange coefficient. In this case, the APDU is: CLA=90, INS=13, P1= card identifier, P2=00, Lc=20 and data=Lagrange coefficient.
		4. We have to send data to decrypt, concretely Y2 and Y1. In this case, the APDU is: CLA=90, INS=1D, P1-P2=00, Lc=20 and data=Y2+Y1.


5. Verification

		1. We have to initialize the applet. In this case the applet identifier is 3132333433123450.
		2. We have to verify share and share commitment.
			- The APDU used to verify share is: CLA=80, INS=A0, P1-P2=00.
			- The APDU used to verify share commitment is: CLA=80, INS=B0, P1-P2=00.


You can fin more information about the implementation in the section Development Details of the <a href="https://raw.github.com/CRISES-URV/eVerification-2/master/extendedpaper.pdf">extendedpaper.pdf</a>


##License

This software is released under BSD 3-clause license which is contained in the file <a href="https://github.com/CRISES-URV/eVerification-2/blob/master/LICENSE">LICENSE</a>.


##Future Work

As a future work, we are working in a non-trusted third party (Non-TTP)
solution with a distributed generation of the shares. In addition, we would like
to improve the eﬃciency, time and storage of the protocol in smartcard (i.e.,
using ElGamal on elliptic curves).


#Bibliography

<a name="ref1"></a>[1] Cramer, R., Gennaro, R., Schoenmakers, B.: A secure and optimally ecient
multi-authority election scheme. In: Proceedings of the 16th annual international
conference on Theory and application of cryptographic techniques. pp. 103{118.
EUROCRYPT'97, Springer-Verlag, Berlin, Heidelberg (1997), 
http://portal.acm.org/citation.cfm?id=1754542.1754554

<a name="ref2"></a>[2] J. Pujol-Ahullo, R. Jardi-Cedo, J. Castella-Roca, O. Farràs , 
"TTP SmartCard - based ElGamal Cryptosystem using Threshold Scheme for Electronic Elections ", 
Foundations & Practice of Security 2011 - FPS 2011, Paris, France, May 2011. 
http://crises2-deim.urv.cat/docs/publications/conferences/656.pdf

