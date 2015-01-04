#include "cryptoutils.h"

uint8_t hex_to_int (uint8_t c) {
  uint8_t v = 0;
  if ((c>=0x30)&&(c<=0x39))
    v = c - 0x30;
  if ((c>=0x41)&&(c<=0x46))
    v = c - 0x37;
  if ((c>=0x61)&&(c<=0x66))
    v = c - 0x57;
  return v;
}

uint32_t read_32_bits (char* hex_str) {
  uint32_t len;
  uint32_t val;
  uint8_t i;
  uint8_t c;
  uint8_t v;
  len = strlen (hex_str);
  if (len<8) {
    Serial.println();
    Serial.print ("length : ");
    Serial.println (len);
    Serial.println ("problem, length less than 8 in read_32_bits");
    Serial.println (hex_str);
    return 0;
  }
  
  val = 0;
  for (i=0;i<8;i++) {
    val<<=4;
    c = hex_str[i];
    v = hex_to_int (c);
    val |= v;
  }
  return val;
}

uint64_t read_64_bits (char* hex_str) {
  uint32_t len;
  uint64_t val;
  uint8_t i;
  uint8_t c;
  uint8_t v;
  len = strlen (hex_str);
  if (len<16) {
    Serial.println();
    Serial.print ("length : ");
    Serial.println (len);
    Serial.println ("problem, length less than 8 in read_32_bits");
    Serial.println (hex_str);
    return 0;
  }
  
  val = 0;
  for (i=0;i<16;i++) {
    val<<=4;
    c = hex_str[i];
    v = hex_to_int (c);
    val |= v;
  }
  return val;
}

#define HEX_DIGIT(v) ( ( ((v)>=0) && ((v)<=15) ) \
                       ? \
                         ( ((v)>=10) ? ((char) ((v)+0x57)) : ((char) ((v)+0x30)) ) \
                       : \
                         '?' \
                     )

void _print_32_bits (char* buffer, uint32_t val) {
  uint8_t i;
  uint8_t v;
  for (i=0;i<8;i++)
    buffer[i] = ( HEX_DIGIT ( ( val >> ( (7 - i) * 4 ) ) & 0x0f ) );
}

void print_32_bits (uint32_t val) {
  char buffer[9];
  memset(buffer, 0, sizeof(buffer));
  _print_32_bits (buffer, val);
  Serial.print (buffer);
}

void _print_64_bits (char* buffer, uint64_t val) {
  uint8_t i;
  uint8_t v;
  for (i=0;i<16;i++)
    buffer[i] = ( HEX_DIGIT ( ( val >> ( (15 - i) * 4 ) ) & 0x0f ) );
}

void print_64_bits (uint64_t val) {
  char buffer[17];
  memset(buffer, 0, sizeof(buffer));
  _print_64_bits (buffer, val);
  Serial.print (buffer);
}

/********************************************************************************
 * testing functionnality
 *
 */

bool _TEST(bool c) {
  if ((c)) 
    Serial.println("PASS"); 
  else 
    Serial.println("FAIL"); 
  return (c);
}                 

int _test_print_32_bits (void) {
  char expected[] = "123456789abcdef0";;
  char buffer[17];
  int len = 0;
  int res = 0;
  
  memset(buffer, 0, sizeof(buffer));
  Serial.println ("* Testing print_32_bits");
  Serial.println (expected);
  _print_32_bits (buffer, 0x12345678);
  _print_32_bits (buffer+8, 0x9abcdef0);
  Serial.println(buffer);
  len = strlen(expected);
  _TEST ((strncmp(buffer, expected, len)==0));
}

int _test_read_32_bits (void) {
  uint32_t   l;
  char*      s;

  Serial.println ("* Testing read_32_bits");
  s = "01234567";
  Serial.println (s);
  l = read_32_bits (s);
  print_32_bits (l);
  Serial.println();
  _TEST (l==0x01234567);
}

int _test_print_64_bits (void) {
  char expected[] = "123456789abcdef0";;
  char buffer[17];
  int len = 0;
  int res = 0;
  
  memset(buffer, 0, sizeof(buffer));
  Serial.println ("* Testing print_64_bits");
  Serial.println (expected);
  _print_64_bits (buffer, 0x123456789abcdef0);
  Serial.println(buffer);
  len = strlen(expected);
  _TEST ((strncmp(buffer, expected, len)==0));
}

int _test_read_64_bits (void) {
  uint64_t   l;
  char*      s;

  Serial.println ("* Testing read_64_bits");
  s = "0123456789abcdef";
  Serial.println (s);
  l = read_64_bits (s);
  print_64_bits (l);
  Serial.println();
  _TEST (l==0x0123456789abcdef);
}

int test_cryptoutils (void) {
  if (!_test_print_32_bits()) return 0;
  if (!_test_read_32_bits()) return 0;
  if (!_test_print_64_bits()) return 0;
  if (!_test_read_64_bits()) return 0;
  return 1;
}

