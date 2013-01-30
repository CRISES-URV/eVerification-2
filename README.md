<img src="https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoeverification2.png" />

eVeriﬁcation2 TSI-020100-2011-39 is a research project leaded by Scytl Secure Electronic Voting S.A.,
with the collaboration of CRISES research group from Universitat Rovira i Virgili, and supported by 
the Spanish Ministry of Industry, Commerce and Tourism (through the development program AVANZA I+D).

You can find more information about eVerification2 project in http://crises-deim.urv.cat/everification2

<img src="https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logo_planAvanza2.png"  width="300" height="100">

<center><table border="0">
<tr><td align=center valign=top></td>
<td align=center valign=middle><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoScytl.png></td>
<td align=center valign=bottom>
    <br><br><br><br><br><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoURV.png>
</td></tr></table></center>


<center><table>
<tr><td><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoScytl.png></td>
<td><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoURV.png></td></tr>
</table></center>

#TTP SmartCard-Based ElGamal Cryptosystem Using Threshold Scheme for Electronic Elections

As a result of this research project, CRISES group has studied the feasibility of developing ElGamal 
cryptosystem and Shamir’s secret sharing scheme into JavaCards, whose API gives no support for it.

In particular, the contributions of our work have been the design and development for JavaCards of
the following building blocks: (i) ElGamal cryptosystem to generate the ElGamal key pair, (ii) Shamir’s 
secret sharing scheme to divide the private key in a set of shares, (iii) secure communication channels 
for the distribution of the shares, and (iv) a decryption function without reconstructing the private key. 
This solution can be useful for a typical e-voting system, speciﬁcally in the voting scheme presented by 
Cramer et al. [1].

You can find more information about these contributions and how it had been desinged and implemented in the 
conference `paper.pdf` presented in Foundations & Practice of Security 2011 called: TTP SmartCard-Based ElGamal 
Cryptosystem Using Threshold Scheme for Electronic Elections [2]. In the `extendedpaper.pdf`, you can find a 
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

The code is divided in two different parts: client and applet code.
The former part includes the GUI and the code related to manage of the protocol execution. This part has been developed
in Java programming language.
The last part is the code placed/installed into each SC. It is writted in JavaCard.

This libaray has been tested in JCOP 21 v2.2 and Sm@rtcafé Expert 4 cards (you can find information of the results in
the evaluation and conclusion sections of the `paper.pdf` and `extendedpaper.pdf`.


##License

This software is released under BSD 3-clause license which is contained in the file `LICENSE`.


##Future Work

As a future work, we are working in a non-trusted third party (Non-TTP)
solution with a distributed generation of the shares. In addition, we would like
to improve the eﬃciency, time and storage of the protocol in smartcard (i.e.,
using ElGamal on elliptic curves).


#Bibliography

[1] Cramer, R., Gennaro, R., Schoenmakers, B.: A secure and optimally ecient
multi-authority election scheme. In: Proceedings of the 16th annual international
conference on Theory and application of cryptographic techniques. pp. 103{118.
EUROCRYPT'97, Springer-Verlag, Berlin, Heidelberg (1997), http://portal.
acm.org/citation.cfm?id=1754542.1754554

[2] J. Pujol-Ahullo, R. Jardi-Cedo, J. Castella-Roca, O. Farràs , 
"TTP SmartCard - based ElGamal Cryptosystem using Threshold Scheme for Electronic Elections ", 
Foundations & Practice of Security 2011 - FPS 2011, Paris, France, May 2011. 
http://crises2-deim.urv.cat/docs/publications/conferences/656.pdf

