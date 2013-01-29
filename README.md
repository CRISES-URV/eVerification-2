EVERIFICATION2
==============

eVeriﬁcation2 TSI-020100-2011-39 is a research project leaded by Scytl Secure Electronic Voting S.A.,
with the collaboration of CRISES research group from Universitat Rovira i Virgili, and supported by 
the Spanish Ministry of Industry, Commerce and Tourism (through the development program AVANZA I+D).


TTP SmartCard-Based ElGamal Cryptosystem Using Threshold Scheme for Electronic Elections
----------------------------------------------------------------------------------------

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


Software
--------

This libraries implement the protocol described in the paper described above.
TODO: talk about GUI, configuration (t,n), etc.


License
-------

This software is released under BSD 3-clause license which is contained in the file `LICENSE`.


Conclusions and Future Work
---------------------------

We developed a library for Java Cards that allows: (i) a big number storage and
representation and (ii) modular arithmetics. Next, we used the library to design
and implement the ElGamal cryptosystem for the Java Card platform. Please,
note that there is no support for ElGamal cryptosystem in the Java Card API
even though it might be provided by the smartcard hardware. We completed
the library with the development of the Shamir’s (t,n)-threshold scheme for the
ElGamal cryptosystem. Finally, we evaluated the performance and eﬃciency
of our implemented library on a JCOP 21 v2.2 with 72Kb of memory using
diﬀerent key sizes. The encryption and decryption operations show a reasonable
cost although it is not advisable to use these operations massively. The shares
generation and veriﬁcation have a signiﬁcant cost. Nonetheless, we think that
they are aﬀordable because they can be realized only once and before their use.

As a future work, we are working in a non-trusted third party (Non-TTP)
solution with a distributed generation of the shares. In addition, we would like
to improve the eﬃciency, time and storage of the protocol in smartcard (i.e.,
using ElGamal on elliptic curves).


Bibliography
------------
[1] Cramer, R., Gennaro, R., Schoenmakers, B.: A secure and optimally ecient
multi-authority election scheme. In: Proceedings of the 16th annual international
conference on Theory and application of cryptographic techniques. pp. 103{118.
EUROCRYPT'97, Springer-Verlag, Berlin, Heidelberg (1997), http://portal.
acm.org/citation.cfm?id=1754542.1754554

[2] J. Pujol-Ahullo, R. Jardi-Cedo, J. Castella-Roca, O. Farràs , 
"TTP SmartCard - based ElGamal Cryptosystem using Threshold Scheme for Electronic Elections ", 
Foundations & Practice of Security 2011 - FPS 2011, Paris, France, May 2011. 
http://crises2-deim.urv.cat/docs/publications/conferences/656.pdf

