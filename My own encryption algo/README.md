@authors Karthik Srinivaasan Ayengar Devanathan and Anand Ganesh

The algorithm that we designed uses several already known techniques to induce obfuscation and arbitrariness. Let us look at the following figure to understand the steps that the plain text has to undergo before it becomes cipher text.

• The intitializing vector is used to make sure that there is no recurring patterns.
• Once the message is XORed with Initializing vector, it passed through a Permutation-Box for the purpose of diffusion.
• After that, the S-Box operates on it for inducing confusion.
• The key is hashed and is XORed with the resulting cipher from the previous step.
• It constantly undergoes circular shift to make use of all the bits of the key.

The basic algorithm that it follow is CBC chaining. The output of this encryption algorithm was a complex cipher that doesn’t make any sense to humans. Attacking this algorithm using brute-force would be very expensive and it is impossible to break it.

There are not many shortcomings in the algorithm, but one noticeable shortcoming lied in the way we split our key into 4 quarters and XORed it. This might make the attacker to get a piece of plaintext with lesser effort.