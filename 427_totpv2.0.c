#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <stdint.h>

#define RUN  0
#define TEST  1

/////////////////////
// This code based off TOTP RFC 6238 implementation
// https://tools.ietf.org/html/rfc6238
/////////////////////

void printinHex(unsigned char* str){ //print the result in hexidecimal form

	printf("hash=");
	for(int i = 0 ; i < strlen(str) ; i++)
		printf("%u,", str[i]);
	printf("\n");
	printf("strlen = %d\n",strlen(str));
	printf("since each character has 8 bits, there are %u*8=%u bits in the hash\n",strlen(str),8*strlen(str));

}

void reverseString(unsigned char* str){
	int i = 0 , j = strlen(str) - 1;//counter
	while(i < j){
		unsigned char temp = str[i];//temporary buffer for swapping
		str[i] = str[j];
		str[j] = temp;
		i++;//increment the first counter
		j--;//decrement the second counter
	}
}

void binaryComputation(unsigned char* hash){
//print the results in the computation
	printf("Computing offset......\n");
	int offset = hash[strlen(hash) - 1] & 0xf;
	printf("\noffset=%d\n",offset);//print the offset
	printf("hash[offset] =hash[%d]= %d\n",offset,hash[offset]);
	printf("(hash[offset] & 0x7f ) << 24 = %d\n",((hash[offset] & 0x7f ) << 24));
	printf("hash[offset+1] =hash[%d]= %d\n",offset+1,hash[offset+1]);
	printf("((hash[offset+1] & 0xff) << 16) = %d\n",((hash[offset+1] & 0xff) << 16));
	printf("hash[offset+2]=hash[%d] = %d\n",offset+2,hash[offset+2]);
	printf("((hash[offset+2] & 0xff) << 8) = %d\n",((hash[offset+2] & 0xff) << 8));
	printf("hash[offset+3] =hash[%d] = %d\n",offset+3,hash[offset+3]);
	printf("(hash[offset + 3] & 0xff) = %d\n",(hash[offset + 3] & 0xff));
	printf("---------end----------\n");


}

int32_t compute_totp( unsigned char* key, int key_len, unsigned long long int time){

	// compute the MAC
	printf("key = %s\n",key);
	printf("key_len = %d\n",key_len);
	printf("(unsigned long long int) time in hex = %llx\n",time);
	printf("original time in decimal=%llu\n",time);
	//printf("sizeof unsigned int = %d\n",sizeof(unsigned int));



	//unsigned char* _md = malloc(1024*sizeof(unsigned char));//dclare md 
	unsigned char _md[1024];
	unsigned int _md_len = 1024;//get the length of md, excluding the terminating character
	unsigned char ptr_time[1024];//this array will store the time
	sprintf(ptr_time,"%llx",time);// get the content of time into the unsigned char array
	printf("original time in hex=%s\n",ptr_time);
	printf("original time in hex length=%d\n",strlen(ptr_time));
	reverseString(ptr_time);//reverse ptr_time
	
	printf("reversed time in hex=%s\n",ptr_time);
	int time_length = strlen(ptr_time);//get the size of time 

	printf("reversed time length=%d\n",time_length);
	//unsigned char* hash = HMAC(EVP_sha512(), ptr_time, time_length, key, key_len, _md, _md_len);//get the raw hash value from HMAC
	//unsigned char* hash = HMAC(EVP_sha512(), ptr_time, time_length, key, key_len, NULL, NULL);//get the raw hash value from HMAC
	unsigned char* hash = HMAC(EVP_sha512(), key, key_len, ptr_time,time_length, NULL, NULL);//get the raw hash value from HMAC
	//print in hex
	printinHex(hash);	

	// compute the offset

	//print hash[strlen(hash) - 1]
	printf("hash[%d -1]=%d\n",strlen(hash),hash[strlen(hash) - 1]);



	int offset = hash[strlen(hash) - 1] & 0xf;


	binaryComputation(hash);//perform detailed binary computation

	printf("\noffset=%d\n",offset);//print the offset


	int binary = ((hash[offset] & 0x7f ) << 24) | 
			((hash[offset+1] & 0xff) << 16) | 
			((hash[offset+2] & 0xff) << 8)| 
			(hash[offset + 3] & 0xff);
	printf("binary=%d\n",binary);
	unsigned long long int modulus = binary % 100000000;

	printf("modulus = %d\n",modulus);
	getchar();
	// perfrom modulus
	return modulus; 
}

int32_t main (int argc, char *argv[])
{
	int8_t argsok = 0; 
	int8_t mode=0;
	unsigned char seed[] = "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34";

	int length_of_seed = strlen(seed);//get the size of seed, excluding the terminating character

	if (argc > 1){
		if(strncmp(argv[1], "run", 3)==0){
			mode = RUN; 
			argsok=1;
		}
		else if (strncmp(argv[1], "test", 4)==0){
			argsok=1;
			mode = TEST; 
		}
	}
	if(!argsok){
		perror("'./totp test' or './totp run'\n");
		exit(1);
	}
	if (mode == RUN){

		//compute time segment based on current time/period
		time_t t = time(NULL);//get current time
		int t0 = 0;
		unsigned long long int t_int = (t - t0)/30;//declare a variable of the type long long int
		printf("t = %llx\n",t);
		printf("t_int = %llx\n",t_int);
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed,t_int));
	}
	else{
		//what't the datatype of t_int?
		unsigned long long int t_int;//declare a variable of the type long long int
		t_int = 0x0000000000000001;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed, t_int));
		t_int = 0x00000000023523EC; 
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed, t_int));
		t_int = 0x00000000023523ED;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed, t_int));
		t_int = 0x000000000273EF07;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed, t_int));
		t_int = 0x0000000003F940AA;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed, t_int));
		t_int = 0x0000000027BC86AA;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed, t_int));
	}

	return 0;
}
