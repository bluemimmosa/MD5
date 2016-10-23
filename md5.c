#include <stdint.h>
#include <stdio.h>

#define DEBUG

#define ROTL(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))
//typedef unsigned int uint32_t;
void debug_print(char *, uint32_t);
uint32_t padded_length_in_bits(uint32_t len);

typedef struct md5{
	uint32_t digest[4];
	uint32_t k[64];
	int err;
} md5_hash;

uint64_t padded_length_in_bits(uint32_t len){
	if(len%64 == 56){
		len++;
	}
    while((len%64)!=56){
    	len++;
    }
    return len*8;
}

int calculate_md5(md5_hash *_md5, unsigned char *text, uint64_t length){
	unsinged char *buffer;
	uint64_t lb = length*8;

	uint32_t rounds[] = {7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
						 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
						 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
						 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21};

	uint32_t k[] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

	uint32_t no_of_bits = padded_length_in_bits(length);

	#ifdef DEBUG
		printf("\n no of bits = %u",no_of_bits);
	#endif

	buffer = (unsigned char *)malloc((bits/8)+8);
	if(buffer == NULL){
		#ifdef DEBUG
			printf("\nError allocating memory....");
		#endif
		return -1;
	}

	memcpy(buffer, text, length);

	//add 1 on last of the message..
	*(buffer+length) = 0x80);
	//fill remaining by 0x00;
	for(i=length+1; i<(no_of_bits/8); i++){
	*(buffer+i) = 0x00;
	}

	memcpy(buffer+(no_of_bits/8), &lb,8);

	/*append the length to last words... 
	*(buffer +(no_of_bits/8)+7) = (lb>>56) & 0xFF;
	*(buffer +(no_of_bits/8)+6) = (lb>>48) & 0xFF;
	*(buffer +(no_of_bits/8)+5) = (lb>>40) & 0xFF;
	*(buffer +(no_of_bits/8)+4) = (lb>>32) & 0xFF;
	*(buffer +(no_of_bits/8)+3) = (lb>>24) & 0xFF;
	*(buffer +(no_of_bits/8)+2) = (lb>>16) & 0xFF;
    *(buffer +(no_of_bits/8)+1) = (lb>>8) & 0xFF;
    *(buffer +(no_of_bits/8)+0) = (lb>>0) & 0xFF;
    */

    //Initialize variables:
    _md5->digest[0] = 0x67452301;	//A
    _md5->digest[1] = 0xefcdab89;	//B
    _md5->digest[2] = 0x98badcfe;	//C
    _md5->digest[3] = 0x10325476;	//D

    for(i=0; i<((no_of_bits+64)/512); i++){
    	for(j=0;j<64;j++){	//emptying the buffer k[] so that can start fresh
    		_md5->k[j] = 0x00;
    	}
    	//breaking the 512 bit block into 32 bit block 
    	uint32_t *tmp = (uint32_t *) (buffer+i);

    	uint32_t a = _md5->digest[0];
    	uint32_t b = _md5->digest[1];
    	uint32_t c = _md5->digest[2];
    	uint32_t d = _md5->digest[3];

    	for(j=0; j<64;j++){
    		uint32_t f,g;
    		if(i<16){
    			f = (b&c)|((~b)&d);
    			g = j;
    		}
    		else if(j<32){
    			f = (d&b)|((~d)&c);
                g = (5*j+1)%16;
    		}
    		else if(j<48){
    			f = b^c^d;
                g = (3*j+5)%16;    			
    		}
    		else{
    			f = c^(b|(~d));
                g = (7*j)%16;
    		}
    		uint32_t temp = d;
    		d = c;
    		c = b;
    		b = b+ROTL((a+f+k[j]+w[j]),rounds[j]);
    		a = temp;
    	}

    	_md5->digest[0] += a;	//A
    	_md5->digest[1] += b;	//B
    	_md5->digest[2] += c;	//C
   		_md5->digest[3] += d;	//D
    }
    free(buffer);
    return 1;
}
