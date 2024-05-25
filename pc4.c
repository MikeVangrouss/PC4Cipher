/* PC4 Cipher */
/* 49-bit block cipher in ECB Mode for DMR Radio*/
/* by Alexander PUKALL 2015 */
/* Code free for all, even for commercial software */
/* No restriction to use. Public Domain */

/* Use MD2-II */
/* Use Arc4 */
/* Use Splitmix64 */
 
/* PC4 encryption uses key-dependent S-boxes */

/* Key can be hexadecimal or user password */
/* Key size can vary from 8 bits to 2112 bits */

/* PC4 uses 253 encryption rounds */
/* The number of round can be reduced */
/* if the DMR processor is too slow */

/* how to compile : gcc pc4.c -o pc4 */
 
 
#include <stdio.h>
#include <stdint.h>

#define nbround 254 
#define n1 264
short bits[49],temp[49];
uint8_t ptconvert;
uint8_t convert[7];
uint8_t perm[16][256];
uint8_t new1[256];
uint8_t array[49];
uint8_t array2[49];
uint8_t decal[nbround];
uint8_t rngxor[nbround][3];
uint8_t rngxor2[nbround][3];
uint8_t rounds;
uint8_t tab[256];
uint8_t inv[256];
uint8_t permut[3][3]; 
uint64_t bb;
uint64_t x;
uint8_t tot[3];
uint8_t l[2][3],r[2][3];
uint8_t y,totb;
uint32_t result;
uint8_t xyz, count;
uint8_t keys[16]; 
unsigned char array_arc4[256];
int i_arc4,j_arc4;

int x1,x2,i;
unsigned char h2[n1];
unsigned char h1[n1*3];

uint64_t next() {

	uint64_t z = (x += 0x9e3779b97f4a7c15);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;

	return z ^ (z >> 31);
}


void arc4_init(unsigned char key[])

{
       int tmp;
           
       for (i_arc4=0;i_arc4<256;i_arc4++)
       {
          array_arc4[i_arc4]=i_arc4;
       }
       
       
       j_arc4=0;
                 
        for (i_arc4=0;i_arc4<256;i_arc4++)
       {
         j_arc4=(j_arc4+array_arc4[i_arc4]+key[i_arc4%256])%256;
         tmp=array_arc4[i_arc4];
         array_arc4[i_arc4]=array_arc4[j_arc4];
         array_arc4[j_arc4]=tmp;
       }
 
 i_arc4=0;
 j_arc4=0;
}
       
unsigned char arc4_output()

{
       uint8_t rndbyte,decal;
       int tmp, t;

    i_arc4=(i_arc4+1)%256;
    j_arc4=(j_arc4+array_arc4[i_arc4])%256;
    tmp=array_arc4[i_arc4];
    array_arc4[i_arc4]=array_arc4[j_arc4];
    array_arc4[j_arc4]=tmp;
    t=(array_arc4[i_arc4]+array_arc4[j_arc4])%256;

       if (xyz==0) bb=next();
       decal=56-(8*xyz);  
       rndbyte=(bb>>decal)& 0xff;
       xyz++;
       if (xyz==8) xyz=0;
 
    
    if (count==0)
     {
       rndbyte=rndbyte^array_arc4[t];
       count=1;
     }
     else
     {
       rndbyte=rndbyte+array_arc4[t];
       count=0;
     }
     
     
    return(rndbyte);


}


void md2_init()
{
    
   x1 = 0;
   x2 = 0;
    for (i = 0; i < n1; i++)
        h2[i] = 0;
    for (i = 0; i < n1; i++)
        h1[i] = 0;
}

void md2_hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13, 199,  11,  67, 237, 193, 164,  77, 115, 184, 141, 222,  73,
        38, 147,  36, 150,  87,  21, 104,  12,  61, 156, 101, 111, 145,
       119,  22, 207,  35, 198,  37, 171, 167,  80,  30, 219,  28, 213,
       121,  86,  29, 214, 242,   6,   4,  89, 162, 110, 175,  19, 157,
         3,  88, 234,  94, 144, 118, 159, 239, 100,  17, 182, 173, 238,
        68,  16,  79, 132,  54, 163,  52,   9,  58,  57,  55, 229, 192,
       170, 226,  56, 231, 187, 158,  70, 224, 233, 245,  26,  47,  32,
        44, 247,   8, 251,  20, 197, 185, 109, 153, 204, 218,  93, 178,
       212, 137,  84, 174,  24, 120, 130, 149,  72, 180, 181, 208, 255,
       189, 152,  18, 143, 176,  60, 249,  27, 227, 128, 139, 243, 253,
        59, 123, 172, 108, 211,  96, 138,  10, 215,  42, 225,  40,  81,
        65,  90,  25,  98, 126, 154,  64, 124, 116, 122,   5,   1, 168,
        83, 190, 131, 191, 244, 240, 235, 177, 155, 228, 125,  66,  43,
       201, 248, 220, 129, 188, 230,  62,  75,  71,  78,  34,  31, 216,
       254, 136,  91, 114, 106,  46, 217, 196,  92, 151, 209, 133,  51,
       236,  33, 252, 127, 179,  69,   7, 183, 105, 146,  97,  39,  15,
       205, 112, 200, 166, 223,  45,  48, 246, 186,  41, 148, 140, 107,
        76,  85,  95, 194, 142,  50,  49, 134,  23, 135, 169, 221, 210,
       203,  63, 165,  82, 161, 202,  53,  14, 206, 232, 103, 102, 195,
       117, 250,  99,   0,  74, 160, 241,   2, 113};
       
    int b1,b2,b3,b4,b5;
   
	b4=0;
    while (b6) {
    
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];

            x1 = h2[x2] ^= s4[b5 ^ x1];
        }

        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
           }
          }
        }

void md2_end(unsigned char h4[n1])
{
    
    unsigned char h3[n1];
    int i, n4;
    
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    md2_hashing(h3, n4);
    md2_hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}

int mixy(int nn2) 
{
int maxo;
maxo = arc4_output();
return (maxo%nn2);
}

void mixer(uint8_t *mixu, int nn) 
{
   int ii, jj, tmmp;
      for (ii = nn - 1; ii > 0; ii--) 
       {
          jj = mixy(ii + 1);
          tmmp = mixu[jj];
          mixu[jj] = mixu[ii];
          mixu[ii] = tmmp;
       }
}

void create_keys(unsigned char key1[], size_t size1)
{
    
     int i,w,k;
     unsigned char h4[n1];
       
	     md2_init();
       md2_hashing(key1, size1);
       md2_end(h4);
       
       for (i=0;i<16;i++) keys[i]=h4[i];
       
       arc4_init(h4);
       
       x=0;
       for (i=0;i<8;i++) x=(x<<8)+(h4[256+i]&0xff);
      
       xyz=0;
       count=0;
              
     for (i=0;i<20000;i++) arc4_output();

      uint8_t numbers[256];
       
     for (w=0;w<16;w++)
      {
         
       k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
        
        for (i = 0; i < 256; i++) {numbers[i]= i;}

       mixer(numbers, 256);

        for ( i = 0; i < 256; i++) 
        {
          perm[w][i]=numbers[i];
        }

      }
    
       k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
    
       for (int i = 0; i < 256; i++) {numbers[i]= i;}

        mixer(numbers, 256);

        for (int i = 0; i < 256; i++) 
        {
          new1[i]=numbers[i];
        }

       k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();

      for (int i = 0; i < 49; i++) {numbers[i]= i;}

        mixer(numbers, 49);

           for (int i = 0; i < 49; i++)
           {
              array[i]=numbers[i];
           }
    
      k=arc4_output()+256;  
      for (i=0;i<k;i++) arc4_output();
       
    for (int i=0;i<nbround;i++) 
    {
      decal[i]=(arc4_output()%23)+1;
    }
    
      k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
       
    for (w=0;w<3;w++)
    {
        for (int i=0;i<nbround;i++)
        {
            rngxor[i][w]=arc4_output();
        }
    }

  k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
       
for (int i = 0; i < 49; i++) {numbers[i]= i;}

        mixer(numbers, 49);

           for (int i = 0; i < 49; i++)
           {
              array2[i]=numbers[i];
           }
   
     k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
       
    for (int i = 0; i < 256; i++) {numbers[i]= i;}

        mixer(numbers, 256);

        for (int i = 0; i < 256; i++) 
        {
          tab[i]=numbers[i];
          inv[tab[i]] = (unsigned char)i;
        }
    
     k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
       
        for (w=0;w<3;w++)
      {
    
       k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
       
        for (i = 0; i < 3; i++) {numbers[i]= i;}

       mixer(numbers, 3);

        for ( i = 0; i < 3; i++) 
        {
          permut[w][i]=numbers[i];
        }
      }
      
         k=arc4_output()+256;  
       for (i=0;i<k;i++) arc4_output();
       
    for (w=0;w<3;w++)
    {
        for (int i=0;i<nbround;i++)
        {
            rngxor2[i][w]=arc4_output();
        }
    }
       
       
  }

uint32_t ror(uint32_t x,int shift,int bits)
    {
                      
    uint32_t m0=(1<<(bits-shift))-1;   
                                  
    uint32_t m1=(1<<shift)-1;         
                                   
    return ((x>>shift)&m0) | ((x&m1)<<(bits-shift));
    }
    
uint32_t rol(uint32_t x,int shift,int bits)
    {
    
                      
    uint32_t m0=(1<<(bits-shift))-1;   
                                   
    uint32_t m1=(1<<shift)-1;          
                                   
    return ((x&m0)<<shift) | ((x>>(bits-shift))&m1);
    }

void compute(uint8_t *tab1, uint8_t round)
{
 tot[0]=(perm[round][tab1[permut[0][0]]]+perm[round][tab1[permut[0][1]]])^perm[round][tab1[permut[0][2]]];
 tot[0]=tot[0]+new1[tot[0]]; 
 tot[1]=(perm[round][tab1[permut[1][0]]]+perm[round][tab1[permut[1][1]]])^perm[round][tab1[permut[1][2]]];
 tot[1]=tot[1]+new1[tot[1]]; 
 tot[2]=(perm[round][tab1[permut[2][0]]]+perm[round][tab1[permut[2][1]]])^perm[round][tab1[permut[2][2]]];
 tot[2]=tot[2]+new1[tot[2]]; 
}

void pc4encrypt()
{
 int i;
 totb=0;
	
  for (int i=0;i<3;i++)
  {
    l[0][i]=convert[i];
    r[0][i]=convert[i+3];
  }


  for (int i=1;i<=rounds;i++) 
  {
       totb=totb^r[(i-1)%2][0];
       totb=totb^r[(i-1)%2][1];
       totb=totb^r[(i-1)%2][2];
       
       r[(i-1)%2][0]=r[(i-1)%2][0] + ((unsigned char)~rngxor2[rounds-i][0]);
       r[(i-1)%2][1]=r[(i-1)%2][1] ^ ((unsigned char)~rngxor2[rounds-i][1]);
       r[(i-1)%2][2]=r[(i-1)%2][2] + ((unsigned char)~rngxor2[rounds-i][2]);
       
       result=0;
       result=result+(r[(i-1)%2][0]<<16);
       result=result+(r[(i-1)%2][1]<<8);
       result=(result+r[(i-1)%2][2]);
        
       result=rol(result,decal[i-1],24);
    
               
       r[(i-1)%2][0]=result>>16;
       r[(i-1)%2][1]=(result>>8)& 0xff;
       r[(i-1)%2][2]=result & 0xff; 
       
       
       r[(i-1)%2][0]=tab[(r[(i-1)%2][0])];
       r[(i-1)%2][0]=r[(i-1)%2][0] ^ rngxor[i-1][0];
       
       r[(i-1)%2][1]=inv[(r[(i-1)%2][1])];
       r[(i-1)%2][1]=r[(i-1)%2][1] - rngxor[i-1][1];
       
       r[(i-1)%2][2]=tab[(r[(i-1)%2][2])];
       r[(i-1)%2][2]=r[(i-1)%2][2] ^ rngxor[i-1][2];
       
       
       compute(r[(i-1)%2],(i-1)%16);

         
       l[i%2][0]=r[(i-1)%2][0];
       r[i%2][0]=l[(i-1)%2][0] -tot[0];
      
       l[i%2][1]=r[(i-1)%2][1]; 
       r[i%2][1]=l[(i-1)%2][1] ^tot[1];
       
       l[i%2][2]=r[(i-1)%2][2]; 
       r[i%2][2]=l[(i-1)%2][2] -tot[2];
             
  }
 

  for (i=0;i<3;i++)
  {
    convert[i+3]=l[(rounds-1)%2][i];
    convert[i]=r[(rounds-1)%2][i];
  }


 totb=totb%2;
 
}

void pc4decrypt()

{
	int i;
  totb=0;
	
	 for (i=0;i<3;i++)
  {
    l[0][i]=convert[i];
    r[0][i]=convert[i+3];
  }
 
  y=(rounds-1)%16;
  if (y==0) y=16;  
         
  for (i=1;i<=rounds;i++)
  {
       y--;
       compute(r[(i-1)%2],y);
       if (y==0) y=16;
     
       result=0;
       
       l[(i-1)%2][0]=l[(i-1)%2][0] ^ rngxor[rounds-i][0];
       l[(i-1)%2][0]=inv[(l[(i-1)%2][0])]; 
       
       l[(i-1)%2][1]=l[(i-1)%2][1] + rngxor[rounds-i][1];
       l[(i-1)%2][1]=tab[(l[(i-1)%2][1])]; 
       
       l[(i-1)%2][2]=l[(i-1)%2][2] ^ rngxor[rounds-i][2];
       l[(i-1)%2][2]=inv[(l[(i-1)%2][2])]; 
       
           
       
       result=result+(l[(i-1)%2][0]<<16);
       result=result+(l[(i-1)%2][1]<<8);
       result=(result+l[(i-1)%2][2]);
  
       result=ror(result,decal[rounds-i],24);
  
         
       l[(i-1)%2][0]=result>>16;
       l[(i-1)%2][1]=(result>>8)& 0xff;
       l[(i-1)%2][2]=result & 0xff;
       
       
       l[(i-1)%2][0]=l[(i-1)%2][0] - ((unsigned char)~rngxor2[i-1][0]);
       l[(i-1)%2][1]=l[(i-1)%2][1] ^ ((unsigned char)~rngxor2[i-1][1]);
       l[(i-1)%2][2]=l[(i-1)%2][2] - ((unsigned char)~rngxor2[i-1][2]);
      
       totb=totb^l[(i-1)%2][0];
       totb=totb^l[(i-1)%2][1];
       totb=totb^l[(i-1)%2][2];
       
       l[i%2][0]=r[(i-1)%2][0]; 
       r[i%2][0]=l[(i-1)%2][0] + tot[0];
       
       l[i%2][1]=r[(i-1)%2][1]; 
       r[i%2][1]=l[(i-1)%2][1] ^ tot[1];
       
       l[i%2][2]=r[(i-1)%2][2]; 
       r[i%2][2]=l[(i-1)%2][2] + tot[2];
     

  }
 

  for (i=0;i<3;i++)
  {
    convert[i+3]=l[(rounds-1)%2][i];
    convert[i]=r[(rounds-1)%2][i];
  }
 
 
  totb=totb%2;
  
}
	
void binhex(short *z, int length){

    short *b;
  b=(short *)z; 
 
    uint8_t i,j;
 
    for(i = 0; i < length; i = j){
        uint8_t a = 0; 
        for(j = i; j < i+8; ++j){ 
            a |= b[((7-(j%8))+j)-(j%8)]<<(j-i); 
        }
       convert[ptconvert]=a;
       ptconvert++;
       
    }           
}

void hexbin(short *q, uint8_t w, uint8_t hex) {
    
       short *bits; 
  bits=(short *)q; 
  
    for (uint8_t i = 0; i < 8; ++i) {
        bits[(7+w)-i] = (hex >> i) & 1;
        
    }
}

void main()
{
	rounds=254;
    
   
    // Plaintext frame // 
    uint8_t frame1[49]={
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0};
	
    uint8_t i,w;
     
       
    // KEY 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
    unsigned char data[16]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; 
    
    /* The key creation procedure is very slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many frames as you want without having to recreate the key. */
    
    create_keys(data,16); // KEY creation : key, length of key
    
   printf("\nENCRYPTION PROCESS with key 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01\n"); 
    
      
   for (i=0;i<49;i++) bits[i]=frame1[i];
   
   printf("Plaintext Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);
   
   for (i=0; i<49; i++) temp[i]=bits[array[i]];
   for (i=0; i<49; i++) bits[i]=temp[i];

	ptconvert=0;
  binhex(bits, 48);

	pc4encrypt();

 	for (int q=0;q<6;q++)
	{
	w=q*8;
	hexbin(bits, w,convert[q]);
    }

   bits[48]=bits[48]^totb;
   
   for (i=0; i<49; i++) temp[array2[i]]=bits[i];
   for (i=0; i<49; i++) bits[i]=temp[i];


   printf("\nEncrypted Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);
    
   printf("\n\nDECRYPTION PROCESS with key 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01\n");
   
     
    printf("Encrypted Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);
    
    
   for (i=0; i<49; i++) temp[i]=bits[array2[i]];
   for (i=0; i<49; i++) bits[i]=temp[i];
    
   ptconvert=0;
   binhex(bits, 48);

   pc4decrypt();

  for (int q=0;q<6;q++)
	{
	w=q*8;
	hexbin(bits, w,convert[q]);
    }
    
   bits[48]=bits[48]^totb;
    
   for (i=0; i<49; i++) temp[array[i]]=bits[i];
   for (i=0; i<49; i++) bits[i]=temp[i];

   printf("\nDecrypted Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);


     /*     USER PASSWORD               */
     
     // plaintext frame
      uint8_t frame2[49]={
	0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,
	0,0,1,0,0,0,0,0,1};
     
    /* The key creation procedure is very slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many frames as you want without having to recreate the key. */
    
    create_keys("My Top Secret Password!",23); // KEY creation : password, length of password
    
   printf("\n\nENCRYPTION PROCESS with user password 'My Top Secret Password!'\n"); 
   
   for (i=0;i<49;i++) bits[i]=frame2[i];
   
   printf("Plaintext Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);
   
     
   for (i=0; i<49; i++) temp[i]=bits[array[i]];
   for (i=0; i<49; i++) bits[i]=temp[i];

	ptconvert=0;
  binhex(bits, 48);

	pc4encrypt();

 	for (int q=0;q<6;q++)
	{
	w=q*8;
	hexbin(bits, w,convert[q]);
    }

   bits[48]=bits[48]^totb;
   
   for (i=0; i<49; i++) temp[array2[i]]=bits[i];
   for (i=0; i<49; i++) bits[i]=temp[i];


   printf("\nEncrypted Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);
    
   printf("\n\nDECRYPTION PROCESS with user password 'My Top Secret Password!'\n");
   
     
    printf("Encrypted Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);
    
    
   for (i=0; i<49; i++) temp[i]=bits[array2[i]];
   for (i=0; i<49; i++) bits[i]=temp[i];
    
   ptconvert=0;
   binhex(bits, 48);

   pc4decrypt();

  for (int q=0;q<6;q++)
	{
	w=q*8;
	hexbin(bits, w,convert[q]);
    }
   
   bits[48]=bits[48]^totb;
    
   for (i=0; i<49; i++) temp[array[i]]=bits[i];
   for (i=0; i<49; i++) bits[i]=temp[i];

   printf("\nDecrypted Frame :\n");
   for (i=0;i<49;i++) printf("%d",bits[i]);

	printf("\n");


}

/*  
ENCRYPTION PROCESS with key 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
Plaintext Frame :
0000000000000000000000000000000000000000000000000
Encrypted Frame :
1000110101001100000100001000111011010010001001101

DECRYPTION PROCESS with key 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
Encrypted Frame :
1000110101001100000100001000111011010010001001101
Decrypted Frame :
0000000000000000000000000000000000000000000000000

ENCRYPTION PROCESS with user password 'My Top Secret Password!'
Plaintext Frame :
0010000001000000001000000000000010000000001000001
Encrypted Frame :
0000011100110010010110111010110010110100000110100

DECRYPTION PROCESS with user password 'My Top Secret Password!'
Encrypted Frame :
0000011100110010010110111010110010110100000110100
Decrypted Frame :
0010000001000000001000000000000010000000001000001
*/
