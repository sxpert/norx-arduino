#ifndef __cryptoutils_h_
#define __cryptoutils_h_

#include "Arduino.h"


uint32_t read_32_bits (char* hex_str);
uint64_t read_64_bits (char* hex_str);
void print_32_bits (uint32_t val);
void print_64_bits (uint64_t val);
bool _TEST(bool c);
int test_cryptoutils (void);


#endif
