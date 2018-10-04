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

	//printf("hash=");
	for(int i = 0 ; i < 64 ; i++)
		printf("%x,", str[i]);
	printf("\n");
	//printf("strlen = %d\n",strlen(str));
	//printf("since each character has 8 bits, there are %u*8=%u bits in the hash\n",strlen(str),8*strlen(str));

}

uint64_t ChangeEndianness(uint64_t value)
{
    uint64_t result = 0x00000000000000;
    result |= (value & 0x00000000000000FF) << 56u;
    result |= (value & 0xFF00000000000000) >> 56u;
    result |= (value & 0x000000000000FF00) << 40u;
    result |= (value & 0x00FF000000000000) >> 40u;
    result |= (value & 0x0000000000FF0000) << 24u;
    result |= (value & 0x0000FF0000000000) >> 24u;
    result |= (value & 0x00000000FF000000) << 8u;
    result |= (value & 0x000000FF00000000) >> 8u;
    return result;
}


uint32_t compute_totp( unsigned char* key, uint64_t key_len, uint64_t time){

	// compute the MAC	
	//change endianness
	uint64_t time_reversed = be64toh(time);
	unsigned char* ptr_time = &time_reversed;
	int time_length = sizeof(time_reversed);//get the size of time 


	//printf("\nreversed time length=%d\n",time_length);
	//unsigned char* hash = HMAC(EVP_sha512(), key, key_len, ptr_time, time_length, _md, &_md_len);//get the raw hash value from HMAC
	//unsigned char* hash = HMAC(EVP_sha512(), ptr_time, time_length, key, key_len, NULL, NULL);//get the raw hash value from HMAC
	//unsigned char hash[64];
	
	//strcpy(hash,HMAC(EVP_sha512(), key, key_len, ptr_time,time_length, NULL, NULL));//get the raw hash value from HMAC
	unsigned char* hash = HMAC(EVP_sha512(), key, key_len, ptr_time,time_length, NULL, NULL);//get the raw hash value from HMAC
	
	//printf("hash=");
	//printinHex(hash);//print the hash
	//printf("hash.len=%d\n",strlen(hash));
	uint32_t offset = hash[64 - 1] & 0xf;
	//printf("offset=%d\n",offset);//print the offset


	int binary = ((hash[offset] & 0x7f ) << 24) |
			((hash[offset+1] & 0xff) << 16) |	
			((hash[offset+2] & 0xff) << 8) | 
			(hash[offset + 3] & 0xff);
	//printf("binary=%d\n",binary);
	int modulus = binary % 100000000;
	return modulus; 
}

int32_t main (int argc, char *argv[])
{
	int8_t argsok = 0; 
	int8_t mode=0;
	unsigned char seed[] = "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34";

	uint64_t length_of_seed = strlen(seed);

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
		uint64_t t_int = (t - t0)/30;//declare a variable of the type long long int
		//printf("t = %llx\n",t);
		//printf("t_int = %llx\n",t_int);
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,length_of_seed,t_int));
	}
	else{
		//what't the datatype of t_int?
		uint64_t t_int;//declare a variable of the type long long int
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
