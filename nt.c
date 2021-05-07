#include <stdio.h>
#include <string.h>
#include <pbc/pbc.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
//#include <stdlib.h>
#include <openssl/evp.h>

#define HASH_LEN 64

pairing_t pairing;
int k,t=3,nf;
element_t g,sko,pko,sku,pku1,pku2,sks,pks,a,b,c,d,f,K,td1,td2,sig1,sig2,sig2dash,sig3;

//intialising some random dictionary of files and keywords
//I took 3 files with 4 keywords in each
char *files[] = {"file1","file2","file3"};
char *indices[] = {"index1","index2","index3"};

//these are the files being used
char *file1[] = {"word11","word12","word13","word14"};
char *file2[] = {"word21","word22","word23","word24"};
char *file3[] = {"word31","word32","word33","word34"}; 

//contains keywords index generated in step1 of ciphertext generation
element_t ind[3][4];

//Ci and Ni using symmetric encryption algorithm for files and file indices
char *C[10],*N[10];

//to store Mi which is hash result of M i = H1 (N i , C i )
char *M[10];

//hash function h: { 0, 1 }∗ -> Zp 
void h(char *in,element_t *out){
	char salt[20] = "first_hash_function";
	char hash[HASH_LEN];
	int len,salt_len;
	len=strlen(in);
	salt_len=strlen(salt);
	PKCS5_PBKDF2_HMAC_SHA1(in, len, salt, salt_len, 1, HASH_LEN, hash);
	element_init_Zr(*out,pairing);
	element_from_hash(*out, hash, HASH_LEN);
}

//hash function H1 : { 0, 1 }∗ x { 0, 1 }∗ -> { 0, 1 }∗
char *H1(char *in1, char *in2){
	
	//char hash[HASH_LEN];
	char *hash = (char *)malloc(HASH_LEN);
	int len1,len2;
	len1 = strlen(in1);
	len2 = strlen(in2);
	PKCS5_PBKDF2_HMAC_SHA1(in1,len1,in2,len2,1,HASH_LEN,hash);
	//char *hashvalue = hash ;
	//for(int i=0;i<HASH_LEN;i++) printf("%02x",hash[i]);
	return hash;
}

char *encryption(char *input,element_t K){
	mpz_t z;
	element_to_mpz(z,K);
	//gmp_printf("attempt 3: %Zd \n", z);

	//printf("%s\n",input + (char)z);
	//return input+ (char)z ;
	return input;
}

void setup()
{
	k=1024;
	element_init_G1(g,pairing);
	element_random(g);
}

void KeyGeneration(){

	//element_t a,b,c,d,f;
	

	//for data owner
	printf("for data owner\n\n");
	element_init_Zr(a,pairing);
	element_init_G1(pko,pairing);
	element_random(a);
	element_printf("SKo = %B\n\n",a);
	element_pow_zn(pko,g,a);
	element_printf("PKo = %B\n\n",pko);
	
	//for data user
	printf("for data user\n\n");
	element_init_Zr(b,pairing);
	element_init_Zr(f,pairing);
	element_init_G1(pku2,pairing);
	element_random(b);
	element_printf("SKu = %B\n\n",b);
	
	//pku2 =  g^b
	element_pow_zn(pku2,g,b);
	
	//pku1 apply mapping pku1 = e(g,g)^(1/b)
	element_init_GT(d,pairing);
	pairing_apply(d,g,g,pairing);
	element_init_GT(pku1,pairing);
	//calculate inverse of b and store inside f
	element_invert(f,b);
	element_pow_zn(pku1,d,f);
	element_printf("PKu1 = %B\n\n",pku1);
	
	
	element_printf("PKu2 = %B\n\n",pku2);
	
	
	//for cloud server
	printf("for cloud server\n\n");
	element_init_Zr(c,pairing);
	element_random(c);
	element_init_G1(pks,pairing);
	element_printf("SKs = %B\n\n",c);
	element_pow_zn(pks,g,c);
	element_printf("PKs = %B\n\n",pks);
	
}

void ciphertext_generation(){
	//printf("%s\n",keyword[0]);
	//generating index I for each word in the files	
	printf("*** CIPHER TEXT GENERATION ***\n\n");
	
	for(int i=0;i<3;i++){
		element_t r;
		element_init_Zr(r,pairing);
		element_random(r);
		
		//index for I i,0
		element_t i0;
		element_init_GT(i0,pairing);
		element_init_GT(ind[i][0],pairing);
		pairing_apply(i0,g,g,pairing);
		element_pow_zn(ind[i][0],i0,r);
		
		//index for I i,1
		element_init_G1(ind[i][1],pairing);
		element_pow_zn(ind[i][1],pku2,r);
		
		//index for I i,2
		element_init_GT(ind[i][2],pairing);
		element_pow_zn(ind[i][2],ind[i][0],a);
		element_pow_zn(ind[i][2],ind[i][2],f);
		
		//index for I i,3
		char *wj;
		if(i==0) wj = file1[3];
		else if(i==1) wj = file2[3];
		else wj = file3[3];
		
		element_t e2;
		element_init_Zr(e2,pairing);
		h(wj,&e2);
		element_neg(e2,e2);
		element_init_GT(ind[i][3],pairing);
		element_pow_zn(ind[i][3],ind[i][0],e2);
		
	}
	
	//generating K, the shared key for DO and Du
	element_init_G1(K,pairing);
	element_pow_zn(K,g,b);
	element_pow_zn(K,g,a);
	
	element_printf("shared key for encryption K = %B\n\n",K);
	
	// generating Ci and Ni using symmetric encryption
	//nf = number of files
	nf = sizeof(files)/sizeof(files[0]);
	//printf("%d\n",nf);
	
	for(int i=0;i<nf;i++){
		C[i] = encryption(files[i],K);
		N[i] = encryption(indices[i],K);
	}
	//printf("%s\n%s\n",C[0],N[0]);
	
	for(int i=0;i<nf;i++){
		M[i] = H1(N[i],C[i]);
	}
	
}



//trapdoor algorithm which is runned by Data User
void trapdoor(){

	printf("*** TRAPDOOR ***\n\n");
	//its calculated by data user and has 2 parts
	//T w',1 is stored in td1
	
	element_init_Zr(td1,pairing);
	element_random(td1);
	
	//T w',2 is stored in td2
	//hs = hash_sum store sum of hash values of all keywords
	element_t hs,temp,temp2,temp3,temp4,temp5,temp6;
	element_init_G1(td2,pairing);
	element_init_Zr(temp,pairing);
	element_init_Zr(temp2,pairing);
	element_init_G1(temp3,pairing);
	element_init_G1(temp4,pairing);
	element_init_Zr(temp5,pairing);
	element_init_Zr(temp6,pairing);
	element_init_Zr(hs,pairing);
	element_set0(hs);
	for(int j=0;j<4;j++){
		h(file1[j],&temp);
		element_add(hs,hs,temp);
	}
	for(int j=0;j<4;j++){
		h(file2[j],&temp);
		element_add(hs,hs,temp);
	}
	for(int j=0;j<4;j++){
		h(file3[j],&temp);
		element_add(hs,hs,temp);
	}
	//store b - hs in temp2 and find its inverse;
	element_sub(temp2,b,hs);
	element_invert(temp6,temp2);
	
	element_pow_zn(temp3,pko,f);
	element_neg(temp5,td1);
	element_pow_zn(temp4,pks,temp5);
	
	element_mul(temp3,temp3,temp4);
	element_pow_zn(td2,temp3,temp6);
	
	
	element_printf("trapdoor1 td1 = %B\n\n",td1);
	element_printf("trapdoor2 td2 = %B\n\n",td2);
	
}

void search(){
	printf("*** SEARCH ***\n\n");
	element_init_GT(sig2dash,pairing);
	element_init_GT(sig2,pairing);
	
	//let i=1
	//SC computes the intermediate value sigma2' and sends to CS
	
	element_pow_zn(sig2dash,ind[1][0],td1);
	element_printf("sigma2' = %B\n\n",sig2dash);
	
	//CS calculates sigma2
	element_pow_zn(sig2,sig2dash,c);
	element_printf("sigma2 = %B\n\n",sig2);
	
	//computing sig3
	//sigma3 is equal to ind[i][2]
	element_printf("sigma3 = %B\n\n",ind[1][2]);
}

void correctness(){
	printf("*** CORRECTNESS ***\n\n");
	//here we will calculate the correctness measure which indicates that the index and trapdoor match successfully.
	//using ciphertext retrieval algo
	//correctness measure is ind[i][2]
	//considering i=1
	
	element_printf("correctness measure = %B\n\n",ind[1][2]);
}


int main(){
	
	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);
	if (!count)
	{
		pbc_die("input error");
	}
	pairing_init_set_buf(pairing, param, count); 
	//setting up the buffer for initialising sample pairing parameters
	
	
	printf("********** IMPLEMENTATION OF BPKEMS **********\n\n");
	
	setup();
	element_t e1,e2;
	element_init_Zr(e1,pairing);
	
	
	printf("*** SETUP ***\n\n");
	
	char *msg1 = "this is message1";
	char *msg2 = "this is message1";
	printf("message1 : %s\nmessage2 : %s\n\n",msg1,msg2);	
	
	h(msg1,&e1);
	element_printf("h = %B\n\n",e1);
	
	
	
	char *output = H1(msg1,msg2);
	//printf("H1 = %s\n\n",output);
	//printf("H1 = %s\n\n",H1(msg1,msg2));
	printf("H1 = ");
	for(int i=0;i<HASH_LEN;i++) printf("%02x",(unsigned char)output[i]);
	printf("\n\n");
	
	
	//key generation
	printf("*** KEY GENERATION ***\n\n");
	KeyGeneration();
	ciphertext_generation();
	trapdoor();
	search();
	correctness();

	return 0;
}










