<a href="http://crises-deim.urv.cat/everification2/" target="_blank"><img src="https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoeverification2.png" />

eVeriﬁcation2 TSI-020100-2011-39 is a research project leaded by Scytl Secure Electronic Voting S.A.,
with the collaboration of CRISES research group from Universitat Rovira i Virgili, and supported by 
the Spanish Ministry of Industry, Commerce and Tourism (through the development program AVANZA I+D).

You can find more information about eVerification2 project in http://crises-deim.urv.cat/everification2

<a href="https://www.planavanza.es" target="_blank"><img src="https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logo_planAvanza2.png"  width="300" height="150">

<center><table border="0">
<tr><td><a href="http://www.scytl.es" target="_blank"><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoScytl.png border="0"></td>
<td><a href="http://www.urv.cat" target="_blank"><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoURV.png border="0"></td>
<td><a href="http://crises-deim.urv.cat" target="_blank"><img src=https://raw.github.com/CRISES-URV/eVerification-2/master/figures/logoCrises.png width="140" height="50" border="0"></td></tr>
</table></center>

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
conference `paper.pdf` presented in Foundations & Practice of Security 2011 called: TTP SmartCard-Based ElGamal 
Cryptosystem Using Threshold Scheme for Electronic Elections [<a href="#ref2">2</a>]. In the `extendedpaper.pdf`, you can find a 
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

You can fin more information about the implementation in the section Development Details of the `extendedpaper.pdf`

##Tests and Results

In order to evaluate the performance and eciency of our implemented protocol over
JavaCards, we carried out a set of tests executing parts of the protocol into JavaCards,
with a (3,5)-threshold. Each test has been run for 10 times on a JCOP 21 v2.2 with
72Kb of memory [1], for a 6 dierent key sizes (512, 736, 896, 1024, 1280 and 2048 bits).
Concretely, the tests have been focused on basic protocol operations entirely executed
on smartcard (not including the operations executed on computer) such as the (i) shares
generation (including ElGamal key pair generation), the (i) share verication (steps 6d
and 6e of electoral board constitution), the (iii) vote encryption and nally, the (iv)
vote decryption without reconstructing the private key.
Results appear in Fig. 5.1, where shares generation and verication costs are the
highest and grow linearly together with the key size. Generating 5 shares ranges from
5.56 to 20.10 minutes, whilst verifying a single share ranges from 1.14 to 4.26 minutes.
Despite their important costs, they are aordable because these operations are realized
only once and before elections start. Encryption cost is reasonable, grows linearly and
ranges from 0.42 to 1.25 minutes. This cost does not depend on the number of shares
though. The decryption cost also grows linearly and ranges from 0.27 to 0.70 minutes.
This behavior is admissible in a real situation where a homomorphic or hybrid e-voting
system is used. However, in e-voting systems purely based on mixnets would not be
viable because votes should be decrypted one by one and, therefore, the total cost would
depend linearly on the number of votes. Notice that this cost does not depend on the
number of shares because each decryption, made in each smartcard of the electoral
board, can be parallelized.
As introduced in Section 4.1.1, Fig. 5.1 depicts a linear growing in time consumption
due to (i) the use of the cryptographic co-processor to execute the costly modular
exponentiation with an almost constant cost, whilst (ii) the rest of modular operations
(such as addition) have the depicted linear cost.




You can find more information of the results in the evaluation and conclusion sections of the <a href="https://raw.github.com/CRISES-URV/eVerification-2/master/paper.pdf">paper.pdf</a> and `extendedpaper.pdf`.


##License

This software is released under BSD 3-clause license which is contained in the file `LICENSE`.


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

