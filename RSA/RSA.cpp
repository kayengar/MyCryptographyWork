#include <iostream>
#include <stdio.h>
#include "BigInt.h"
#include <time.h>
#include <cmath>
#include "RSA.h"
#include "BigInt.h"
#include <stdlib.h>
#define RAND_LIMIT32 0x7FFFFFFF


using namespace std;
using namespace RSAUtil;
void perform_RSA_encryption(RSA q);

unsigned long int *a;
unsigned long int arr[10];


int main()
{
	srand(time( NULL ));
	a=&arr[0];
	
	cout<<"\n 1.a ten random RSA encryptions WITHOUT any parameters";
	
	RSA r[10];
	for (int i = 0; i < 10; ++i)
	{
		perform_RSA_encryption(r[i]);
	}

	cout<<"\n******************************** QUESTION 1********************************";
	cout<<"\n 1.b five large prime numbers as SINGLE arguments";
	
	RSA q(101429);
	perform_RSA_encryption(q);
	RSA q1(100103);
	perform_RSA_encryption(q1);
	RSA q2(100109);
	perform_RSA_encryption(q2);
	RSA q3(100129);
	perform_RSA_encryption(q3);
	RSA q4(103591);
	perform_RSA_encryption(q4);

	
	cout <<"\n 1.c five large PRIME NUMBER PAIRS as arguments";

	RSA qq(101429,101449);
	perform_RSA_encryption(qq);
	RSA qq1(101293,101323);
	perform_RSA_encryption(qq1);
	RSA qq2(101771,101789);
	perform_RSA_encryption(qq2);
	RSA qq3(101533,101537);
	perform_RSA_encryption(qq3);
	RSA qq4(103141,103171);
	perform_RSA_encryption(qq4);

	
	cout<<"\n 1.d TEN large NON-PRIME number pairs as arguments";

	RSA qqq(101428,101448);
	perform_RSA_encryption(qqq);
	RSA qqq1(101292,101322);
	perform_RSA_encryption(qqq1);
	RSA qqq2(101778,101782);
	perform_RSA_encryption(qqq2);    // just randomly made them even numbers to make them non-prime
	RSA qqq3(101536,101534);
	perform_RSA_encryption(qqq3);
	RSA qqq4(103142,103174);
	perform_RSA_encryption(qqq4);
	RSA qqq5(32428,31448);
	perform_RSA_encryption(qqq5);
	RSA qqq6(31292,31322);
	perform_RSA_encryption(qqq6);
	RSA qqq7(30778,31782);
	perform_RSA_encryption(qqq7);    
	RSA qqq8(31536,31534);
	perform_RSA_encryption(qqq8);
	RSA qqq9(33142,33174);
	perform_RSA_encryption(qqq9);

	
	cout<<"\n CHALLENGE RESPONSE scheme\n";

	BigInt message, cipher, deciphered;
    BigInt rsa1_pubkey, rsa1_privatekey;
    BigInt rsa2_pubkey, rsa2_privatekey;
    BigInt rsa1_gnm, rsa2_gnm;

    RSA rsa1, rsa2;
    rsa1_pubkey= rsa1.getPublicKey();
    rsa1_privatekey = rsa1.getPrivateKey();
    rsa1_gnm = rsa1.getModulus();

    cout<<"Public Key ";
    rsa1_pubkey.toULong(a,4);
    cout<<*a<<endl;
 
    rsa1_privatekey.toULong(a,4);
    cout<<"Private Key : "<<*a<<endl;
 	
 	rsa1_gnm.toULong(a,4);
 	cout<<"Modulus (N):"<<*a<<endl;
 	
    // set the same specifications for RSA_2

    rsa2.setN(rsa1_gnm);
    rsa2.setPublicKey(rsa1_pubkey);
    
    message = 7331;
    message.toULong(a,4);
    cout<<"Plain text message is:"<<*a<<endl;

    cipher = rsa2.encrypt(message); // encrypt with rsa 2's public key
    deciphered = rsa1.decrypt(cipher); // decrypt with rsa 1's private key

    cipher.toULong(a,4);
    cout<<"Cipher text:"<<*a<<endl;

    deciphered.toULong(a,4);
    cout<<"deciphered message :"<<*a<<endl;

    cout<<" simple CHALLENGE reseponse was carried out and verified\n";


    
	cout<<"\n BLIND SIGNATURE scheme\n";

	BigInt B_pubkey, B_modulus, random_number, inverse;
	BigInt random_message;
	RSA B;

	B_pubkey = B.getPublicKey();
	B_modulus = B.getModulus();

	random_number = int(((double)rand()/RAND_MAX)*RAND_LIMIT32);
	inverse = modInverse(random_number, B_modulus);

	random_message = int(((double)rand()/RAND_MAX)*RAND_LIMIT32);

	random_message.toULong(a,4);
	cout<<"\n Original message: "<<*a<<endl;

	BigInt intermediate;
	intermediate = B.encrypt(random_number);

	BigInt product;
	product = intermediate * random_message;

	BigInt final_packet;
	final_packet = product % B_modulus;

	// Bob now decrypts the fake message

	BigInt forged;
	forged = B.decrypt(final_packet);

	BigInt retreive;
	retreive = forged * inverse;

	retreive = retreive % B_modulus;

	// to check if this is signed with bob's private key we encrypt it with the public key to get the original message again

	BigInt original_message;
	original_message = B.encrypt(retreive);

	original_message.toULong(a,4);
	cout<<"\n decrypted message = "<<*a<<endl;

	cout<<"\n Thus the original message is now signed without bob realizing it\n";


}

void perform_RSA_encryption(RSA r)
{
	srand( time( NULL ) );
	BigInt message, cipher, deciphered;
	BigInt pubkey, privatekey;
       	BigInt gnm;
       	cout <<"\n\n ************************************ \n\n";
       	pubkey= r.getPublicKey();
       	privatekey = r.getPrivateKey();
       	cout<<"Public Key ";
       	pubkey.toULong(a,4);
       	cout<<*a<<endl;

       	privatekey.toULong(a,4);
       	cout<<"Private Key : "<<*a<<endl;



      	gnm = r.getModulus();
	cout<<"N ( modulus ) "<<gnm.toHexString()<<endl;

     	message = int(((double)rand()/RAND_MAX)*RAND_LIMIT32);

     	cipher = r.encrypt(message);
        deciphered = r.decrypt(cipher);

        cout<<"message: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<endl;
}
