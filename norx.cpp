#include <string.h>
#include <avr/pgmspace.h>
#include "norx.h"
#include "cryptoutils.h"

Norx::Norx (void) {
}

void Norx::begin (uint8_t rounds) {
  Serial.println ("initializing Norx instance");
  this->rounds = rounds;
}

/***************************************************************************
 * crypto functions
 */

void Norx::_XOR_32(stw* w, stw* a, stw* b) {
  w->b32 = (a->b32) ^ (b->b32);
}

void Norx::_XOR_64(stw* w, stw* a, stw* b) {
  w->b64 = (a->b64) ^ (b->b64);
}

void Norx::_AND_32(stw* w, stw* a, stw* b) {
  w->b32 = (a->b32) & (b->b32);
}  

void Norx::_AND_64(stw* w, stw* a, stw* b) {
  w->b64 = (a->b64) & (b->b64);
}  

void Norx::_SHL_32(stw* w, stw* a, uint8_t n) {
  w->b32 = (a->b32) << n;
}

void Norx::_SHL_64(stw* w, stw* a, uint8_t n) {
  w->b64 = (a->b64) << n;
}

void Norx::_ROR_32(stw* w, stw* a, uint8_t n) {
  w->b32 = ((a->b32) >> n) | ((a->b32) << (32 - n ));
}

void Norx::_ROR_64(stw* w, stw* a, uint8_t n) {
  w->b64 = ((a->b64) >> n) | ((a->b64) << (64 - n ));
}

void Norx::_ADX_32(stw* w, stw* a, stw* b) {
  stw w1, w2, w3;
  this->_XOR_32 (&w1, a, b);
  this->_AND_32 (&w2, a, b);
  this->_SHL_32 (&w3, &w2, 1);
  this->_XOR_32 (w, &w1, &w3);
}

void Norx::_ADX_64(stw* w, stw* a, stw* b) {
  stw w1, w2, w3;
  this->_XOR_64 (&w1, a, b);
  this->_AND_64 (&w2, a, b);
  this->_SHL_64 (&w3, &w2, 1);
  this->_XOR_64 (w, &w1, &w3);
}

void Norx::_XRL_32(stw* w, stw* a, stw* b, uint8_t v) {
  stw w1;
  this->_XOR_32 (&w1, a, b);
  this->_ROR_32 (w, &w1, v);
} 

void Norx::_XRL_64(stw* w, stw* a, stw* b, uint8_t v) {
  stw w1;
  this->_XOR_64 (&w1, a, b);
  this->_ROR_64 (w, &w1, v);
} 

void Norx::__G_32 (stw* wa, stw* wb, stw* wc, stw* wd) {
  uint8_t r[4] = {8, 11, 16, 31};

  this->_ADX_32(wa, wa, wb);
  this->_XRL_32(wd, wa, wd, r[0]);
  this->_ADX_32(wc, wc, wd);
  this->_XRL_32(wb, wb, wc, r[1]);
  this->_ADX_32(wa, wa, wb);
  this->_XRL_32(wd, wa, wd, r[2]);
  this->_ADX_32(wc, wc, wd);
  this->_XRL_32(wb, wb, wc, r[3]);
}

void Norx::__G_64 (stw* wa, stw* wb, stw* wc, stw* wd) {
  uint8_t r[4] = {8, 19, 40, 63};

  this->_ADX_64(wa, wa, wb);
  this->_XRL_64(wd, wa, wd, r[0]);
  this->_ADX_64(wc, wc, wd);
  this->_XRL_64(wb, wb, wc, r[1]);
  this->_ADX_64(wa, wa, wb);
  this->_XRL_64(wd, wa, wd, r[2]);
  this->_ADX_64(wc, wc, wd);
  this->_XRL_64(wb, wb, wc, r[3]);
}

void Norx::_G (state_t* s, uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  if (s->bits==32) this->__G_32 (&(s->state[a]), &(s->state[b]), &(s->state[c]), &(s->state[d]));
  if (s->bits==64) this->__G_64 (&(s->state[a]), &(s->state[b]), &(s->state[c]), &(s->state[d]));
}
  
void Norx::_F (state_t* s) {
  // columns
  this->_G (s, 0, 4, 8, 12);
  this->_G (s, 1, 5, 9, 13);
  this->_G (s, 2, 6, 10, 14);
  this->_G (s, 3, 7, 11, 15);
  // diagonals
  this->_G (s, 0, 5, 10, 15);
  this->_G (s, 1, 6, 11, 12);
  this->_G (s, 2, 7, 8, 13);
  this->_G (s, 3, 4, 9, 14);
}
 

/***************************************************************************
 * init functions
 * s => state that is to be modified
 * w => word width in bits (32 or 64)
 * r => number of rounds for f 
 * d => parallelism
 * a => tag size
 * k => key (4 words)
 * n => nonce (2 words)
 */
void Norx::_init (state_t* s, uint8_t w, uint8_t r, uint8_t d, uint8_t a, stw k[4], stw n[2], uint16_t hlen) {
  uint64_t v;
  uint8_t i;
  uint32_t r64;
  uint32_t w64;
  uint32_t d64;
  uint32_t a64;
  
  s->bits = w;
  s->rounds = r;
  
  // set up nonce and key
  
  this->copy_state_word(w, &(n[0]), &(s->state[1]));
  this->copy_state_word(w, &(n[1]), &(s->state[2]));
  
  this->copy_state_word(w, &(k[0]), &(s->state[4]));
  this->copy_state_word(w, &(k[1]), &(s->state[5]));
  this->copy_state_word(w, &(k[2]), &(s->state[6]));
  this->copy_state_word(w, &(k[3]), &(s->state[7]));
  
  // inject constants
  
  if (w==32) {
    s->state[ 0].b32 = 0x243f6a88;
    s->state[ 3].b32 = 0x85a308d3;
    s->state[ 8].b32 = 0x13198a2e;
    s->state[ 9].b32 = 0x03707344;
    s->state[10].b32 = 0x254F537A;
    s->state[11].b32 = 0x38531D48;
    s->state[12].b32 = 0x839C6E83;
    s->state[13].b32 = 0xF97A3AE5;
    s->state[14].b32 = 0x8C91D88C;
    s->state[15].b32 = 0x11EAFB59;
  }
  if (w==64) {
    s->state[ 0].b64 = 0x243f6a8885a308d3;
    s->state[ 3].b64 = 0x13198a2e03707344;
    s->state[ 8].b64 = 0xa4093822299f31d0;
    s->state[ 9].b64 = 0x082efa98ec4e6c89;
    s->state[10].b64 = 0xAE8858DC339325A1;
    s->state[11].b64 = 0x670A134EE52D7FA6;
    s->state[12].b64 = 0xC4316D80CD967541;
    s->state[13].b64 = 0xD21DFBF8B630B762;
    s->state[14].b64 = 0x375A18D261E7F892;
    s->state[15].b64 = 0x343D1F187D92285B;
  }
  this->dump_state(s, "const ");
  
  // integrate parameters

  r64 = r;
  d64 = d;
  w64 = w;
  a64 = a;
 
  v = (r64<<26) | (d64<<18) | (w64<<10) | a64;
  if (w==32) {
    Serial.println("32 bits");
    s->state[14].b32 ^= (uint32_t)v;
    print_32_bits (v);
    Serial.println();
  }
  if (w==64) {
    Serial.println("64 bits");
    s->state[14].b64 ^= v;
    print_64_bits (v);
    Serial.println();
  }
  this->dump_state(s,"parmF ");
  for (i=0;i<r;++i) {
    Serial.println(i);  
    this->_F (s);
    this->dump_state(s, "      ");
  }
  
  this->dump_state(s, "init  ");
}

/***************************************************************************
 * utility functions
 */

void Norx::dump_state_word (uint8_t bits, stw* w) {
  if ((bits&0x7f)==32) print_32_bits(w->b32);
  if ((bits&0x7f)==64) print_64_bits(w->b64);
}

void Norx::empty_state (uint8_t bits, state_t* s) {
  s->bits = bits;
  s->rounds = 0;
  for (uint8_t i=0; i<16; i++) { 
    if (bits==32) s->state[i].b32 = 0x0;
    if (bits==64) s->state[i].b64 = 0x0;
  }
}

void Norx::dump_state (state_t* s, char* prefix) {
  for (uint8_t i=0;i<16;i++) {
    if (i==0)
      Serial.print (prefix);
    else if ((i%4)==0)
      for (uint8_t j=0; j<strlen(prefix);j++)
        Serial.print(' ');
    this->dump_state_word(s->bits, &(s->state[i]));
    if ((i%4)==3) 
      Serial.println();
    else
      Serial.print(' ');
  }
}

void Norx::load_state_word_from_hex (uint8_t bits, stw* w, char* hex_str) {
  if (bits==32) w->b32 = read_32_bits (hex_str);
  if (bits==64) w->b64 = read_64_bits (hex_str);
}

void Norx::copy_state_word (uint8_t bits, stw* s, stw* d) {
  if (bits==32) d->b32 = s->b32;
  if (bits==64) d->b64 = s->b64;
}

void Norx::copy_state (state_t* s, state_t* d) {
  uint8_t i;
  d->bits = s->bits;
  /* bit 7 is used to tell if state is initializing */
  for (i=0;i<16;i++) 
    this->copy_state_word ((s->bits&0x7F), &(s->state[i]), &(d->state[i]));
}

bool Norx::compare_state_word (uint8_t bits, stw* wa, stw* wb) {
  if (bits==32) return (wa->b32)==(wb->b32);
  if (bits==64) return (wa->b64)==(wb->b64);
}

bool Norx::compare_state (state_t* sa, state_t* sb) {
  uint8_t i, c = 0;
  if (sa->bits!=sb->bits)
    return 0;
  for(i=0;i<16;i++)
    if (this->compare_state_word (sa->bits, &(sa->state[i]), &(sb->state[i])))
      c++;
  return (c==16); 
}

/***************************************************************************
 * test procedure
 */

bool Norx::test (void) {
  //if (!test_cryptoutils()) return 0;
  //if (!this->_test_32()) return 0;
  //if (!this->_test_64()) return 0;
  if (!this->_test_F()) return 0;
  if (!this->_test_init()) return 0;
  return 1;
}

bool Norx::_test_32 (void) {
  if (!this->_test_load_state_word_from_hex(32)) return 0;
  if (!this->_test_XOR(32)) return 0;
  if (!this->_test_AND(32)) return 0;
  if (!this->_test_SHL(32)) return 0;
  if (!this->_test_ROR(32)) return 0;
  if (!this->_test_ADX(32)) return 0;
  if (!this->_test_XRL(32)) return 0;
  if (!this->_test_G(32)) return 0;
  return 1;
}

bool Norx::_test_64 (void) {
  if (!this->_test_load_state_word_from_hex(64)) return 0;
  if (!this->_test_XOR(64)) return 0;
  if (!this->_test_AND(64)) return 0;
  if (!this->_test_SHL(64)) return 0;
  if (!this->_test_ROR(64)) return 0;
  if (!this->_test_ADX(64)) return 0;
  if (!this->_test_XRL(64)) return 0;
  if (!this->_test_G(64)) return 0;
}

const char _TEST_A_STR_32[] = "12345678";
const char _TEST_A_STR_64[] = "123456789abcdef0";
const stw  _TEST_A_32 = {0x12345678};
const stw  _TEST_A_64 = {0x123456789abcdef0};
const stw  _TEST_B_32 = {0x23456789};
const stw  _TEST_B_64 = {0x23456789abcdef01};

bool Norx::_test_load_state_word_from_hex (uint8_t bits) {
  stw a;
  stw ea;
  if (bits==32) ea.b32 = _TEST_A_32.b32;
  if (bits==64) ea.b64 = _TEST_A_64.b64;
  Serial.print ("* Testing load_state_word_from_hex");
  Serial.println (bits);
  this->dump_state_word (bits, &ea);
  Serial.println ();
  if (bits==32) this->load_state_word_from_hex(bits, &a, (char*)_TEST_A_STR_32);
  if (bits==64) this->load_state_word_from_hex(bits, &a, (char*)_TEST_A_STR_64);
  this->dump_state_word (bits, &a);
  Serial.println();
  return _TEST (this->compare_state_word(bits, &a, &ea));
}

void Norx::__test_load_a (uint8_t bits, stw* a) {
  if (bits==32) this->copy_state_word (bits, (stw*)&_TEST_A_32, a);
  if (bits==64) this->copy_state_word (bits, (stw*)&_TEST_A_64, a);
}

void Norx::__test_load_a_b (uint8_t bits, stw* a, stw* b) {
  if (bits==32) {
    this->copy_state_word (bits, (stw*)&_TEST_A_32, a);
    this->copy_state_word (bits, (stw*)&_TEST_B_32, b);
  }
  if (bits==64) {
    this->copy_state_word (bits, (stw*)&_TEST_A_64, a);
    this->copy_state_word (bits, (stw*)&_TEST_B_64, b);
  }    
}

bool Norx::_test_XOR (uint8_t bits) {
  stw ew, w, a, b;

  this->__test_load_a_b(bits, &a, &b);
  Serial.print ("* Testing XOR_");
  Serial.println (bits);
  if (bits==32) ew.b32 = 0x317131f1;
  if (bits==64) ew.b64 = 0x317131f1317131f1;
  this->dump_state_word (bits,&ew);
  Serial.println();
  if (bits==32) this->_XOR_32 (&w, &a, &b);
  if (bits==64) this->_XOR_64 (&w, &a, &b);
  this->dump_state_word (bits, &w);
  Serial.println();
  return _TEST (this->compare_state_word(bits, &w, &ew));
}

bool Norx::_test_AND (uint8_t bits) {
  stw ew, w, a, b;

  this->__test_load_a_b(bits, &a, &b);
  Serial.print ("* Testing AND_");
  Serial.println (bits);
  if (bits==32) ew.b32 = 0x02044608;
  if (bits==64) ew.b64 = 0x020446088a8cce00;
  this->dump_state_word (bits, &ew);
  Serial.println();
  if (bits==32) this->_AND_32 (&w, &a, &b);
  if (bits==64) this->_AND_64 (&w, &a, &b);
  this->dump_state_word (bits, &w);
  Serial.println();
  return _TEST (this->compare_state_word(bits, &w, &ew));
}

bool Norx::_test_SHL (uint8_t bits) {
  stw ew, w, a;

  this->__test_load_a(bits, &a);
  Serial.print ("* Testing SHL_");
  Serial.println (bits);
  if (bits==32) ew.b32 = 0x1a2b3c00;
  if (bits==64) ew.b64 = 0x1a2b3c4d5e6f7800;
  this->dump_state_word (bits, &ew);
  Serial.println();
  if (bits==32) this->_SHL_32 (&w, &a, 7);
  if (bits==64) this->_SHL_64 (&w, &a, 7);
  this->dump_state_word (bits, &w);
  Serial.println();
  return _TEST (this->compare_state_word(bits, &w, &ew));
}

bool Norx::_test_ROR (uint8_t bits) {
  stw ew, w, a;

  this->__test_load_a(bits, &a);
  Serial.print ("* Testing ROR_");
  Serial.println (bits);
  if (bits==32) ew.b32 = 0xb3c091a2;
  if (bits==64) ew.b64 = 0xf78091a2b3c4d5e6;
  this->dump_state_word (bits, &ew);
  Serial.println();
  if (bits==32) this->_ROR_32 (&w, &a, 13);
  if (bits==64) this->_ROR_64 (&w, &a, 13);
  this->dump_state_word (bits, &w);
  Serial.println();
  return _TEST (this->compare_state_word(bits, &w, &ew));
}

bool Norx::_test_ADX (uint8_t bits) {
  stw ew, w, a, b;

  this->__test_load_a_b(bits, &a, &b);
  Serial.print ("* Testing ADX_");
  Serial.println (bits);
  if (bits==32) ew.b32 = 0x3579bde1;
  if (bits==64) ew.b64 = 0x3579bde02468adf1;
  this->dump_state_word (bits, &ew);
  Serial.println();
  if (bits==32) this->_ADX_32 (&w, &a, &b);
  if (bits==64) this->_ADX_64 (&w, &a, &b);
  this->dump_state_word (bits, &w);
  Serial.println();
  return _TEST (this->compare_state_word(bits, &w, &ew));
}

bool Norx::_test_XRL (uint8_t bits) {
  stw ew, w, a, b;

  this->__test_load_a_b(bits, &a, &b);
  Serial.print ("* Testing XRL_");
  Serial.println (bits);
  if (bits==32) ew.b32 = 0x3e262e26;
  this->dump_state_word (bits, &ew);
  Serial.println();
  if (bits==32) this->_XRL_32 (&w, &a, &b, 11);
  this->dump_state_word (bits, &w);
  Serial.println();
  return _TEST (this->compare_state_word(bits, &w, &ew));
}


#define G_NB_TEST_VECTORS_32 11
const uint32_t G_TEST_VECTORS_32[][4] PROGMEM = {
  { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
  { 0x00000001, 0x00000000, 0x00000000, 0x00000000 },
  { 0x00000000, 0x00000001, 0x00000000, 0x00000000 },
  { 0x00000000, 0x00000000, 0x00000001, 0x00000000 },
  { 0x00000000, 0x00000000, 0x00000000, 0x00000001 },
  { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
  { 0x00000000, 0x80000000, 0x00000000, 0x00000000 },
  { 0x00000000, 0x00000000, 0x80000000, 0x00000000 },
  { 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
  { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
  { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 }
};
const uint32_t G_TEST_RESULTS_32[][4] PROGMEM = {
  { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
  { 0x00002001, 0x42024200, 0x21010100, 0x20010100 },
  { 0x00202001, 0x42424240, 0x21010120, 0x20010120 },
  { 0x00200000, 0x00400042, 0x00000021, 0x00000020 },
  { 0x00002000, 0x42004200, 0x21000100, 0x20000100 },
  { 0x80001000, 0x21012100, 0x10808080, 0x10008080 },
  { 0x80101000, 0x21212120, 0x10808090, 0x10008090 },
  { 0x00100000, 0x00200021, 0x80000010, 0x00000010 },
  { 0x00001000, 0x21002100, 0x10800080, 0x10000080 },
  { 0xFFFF5FFE, 0x35F939FC, 0x1AFCFCFE, 0x5FFEFEFF },
  { 0xB7BF8099, 0x65A6E720, 0x1E22F5Cb, 0x1AA9E143 }
};

const uint64_t G_TEST_VECTORS_64[][4] PROGMEM = {
  { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
  { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
  { 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000 },
  { 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000 },
  { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001 },
  { 0x8000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
  { 0x0000000000000000, 0x8000000000000000, 0x0000000000000000, 0x0000000000000000 },
  { 0x0000000000000000, 0x0000000000000000, 0x8000000000000000, 0x0000000000000000 },
  { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000 },
  { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
  { 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x0123456789ABCDEF, 0xFEDCBA9876543210 }
};
const uint64_t G_TEST_RESULTS_64[][4] PROGMEM = {
  { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
  { 0x0000002000000001, 0x4200004002020000, 0x2100000001010000, 0x2000000001010000 },
  { 0x0000202000000001, 0x4200404002020040, 0x2100000001010020, 0x2000000001010020 },
  { 0x0000200000000000, 0x0000400000000042, 0x0000000000000021, 0x0000000000000020 },
  { 0x0000002000000000, 0x4200004000020000, 0x2100000000010000, 0x2000000000010000 },
  { 0x8000001000000000, 0x2100002001010000, 0x1080000000808000, 0x1000000000808000 },
  { 0x8000101000000000, 0x2100202001010020, 0x1080000000808010, 0x1000000000808010 },
  { 0x0000100000000000, 0x0000200000000021, 0x8000000000000010, 0x0000000000000010 },
  { 0x0000001000000000, 0x2100002000010000, 0x1080000000008000, 0x1000000000008000 },
  { 0xFFFFFF5FFFFFFFFE, 0x35FFFF3FF9F9FFFC, 0x1AFFFFFFFCFCFFFE, 0x5FFFFFFFFEFEFFFF },
  { 0x06E0F91F53B5CA4B, 0x1D4225AFF0B8887D, 0x26541088639A5752, 0x5A343C6186E9E1DA }
};

void Norx::prgm_copy_state_word (uint8_t bits, void* s, stw* d) {
  if (bits==32) d->b32 = pgm_read_dword ((uint32_t*)(s));
  if (bits==64) {
    uint32_t v;
    v = pgm_read_dword (((uint32_t*)(s))+1);
    d->b64 = v;
    d->b64 <<= 32;
    v = pgm_read_dword ((uint32_t*)(s));
    d->b64 |= v;
  }
}

bool Norx::_test_G_one (uint8_t bits, uint8_t idx) {
  uint8_t i;
  stw w[4], e[4];
  
  if (bits==32) {
    uint32_t* vec32 = (uint32_t*)G_TEST_VECTORS_32;
    uint32_t* res32 = (uint32_t*)G_TEST_RESULTS_32;
    for (i=0;i<4;i++) {
      this->prgm_copy_state_word (bits, (void*)(&(vec32[idx*4+i])), &(w[i]));
      this->prgm_copy_state_word (bits, (void*)(&(res32[idx*4+i])), &(e[i]));
    }
  }
  if (bits==64) {
    uint64_t* vec64 = (uint64_t*)G_TEST_VECTORS_64;
    uint64_t* res64 = (uint64_t*)G_TEST_RESULTS_64;
    for (i=0;i<4;i++) {
      this->prgm_copy_state_word (bits, (void*)(&(vec64[idx*4+i])), &(w[i]));
      this->prgm_copy_state_word (bits, (void*)(&(res64[idx*4+i])), &(e[i]));
    }
  }
  
  Serial.print ("vec ");
  for (i=0;i<4;i++) {
    this->dump_state_word (bits, &(w[i]));
    Serial.print (' ');
  }
  Serial.println ();
  
  if (bits==32) this->__G_32 (&(w[0]), &(w[1]), &(w[2]), &(w[3]));
  if (bits==64) this->__G_64 (&(w[0]), &(w[1]), &(w[2]), &(w[3]));

  Serial.print ("exp ");
  for (i=0;i<4;i++) {
    this->dump_state_word (bits, &(e[i]));
    Serial.print (' ');
  }
  Serial.println ();

  Serial.print ("res ");
  for (i=0;i<4;i++) {
    this->dump_state_word (bits, &(w[i]));
    Serial.print (' ');
  }
  Serial.println ();

  return _TEST (this->compare_state_word(bits, &(w[0]), &(e[0])) | \
                this->compare_state_word(bits, &(w[1]), &(e[1])) | \
                this->compare_state_word(bits, &(w[2]), &(e[2])) | \
                this->compare_state_word(bits, &(w[3]), &(e[3])));
}

bool Norx::_test_G (uint8_t bits) {
  uint8_t i, c = 0;
  stw*    vec;
  stw*    res;
  uint8_t nbvec;
  
  if (bits==32) { nbvec=G_NB_TEST_VECTORS_32; }
    
  Serial.println ("* Testing G");
  for (i=0;i<nbvec;i++)
    if (this->_test_G_one (bits, i))
      c++;
  Serial.print (nbvec);
  Serial.print (" tests done, ");
  Serial.print (c);
  Serial.println (" tests successful");
  return _TEST (c==nbvec);
}

const state_t F_TEST_VECTORS[] PROGMEM = {
  { 0xa0, 0x01, 
          { 0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000 } },
  { 0x20, 0x01,
          { 0x04004001, 0x20200400, 0x20042020, 0x4A4A8A08,
            0x01880885, 0x8A424A40, 0x4A024A02, 0xC24A0248,
            0x41212104, 0x888C4C4A, 0x41210520, 0x05212101,
            0x05012000, 0x20202004, 0x884A4A08, 0x40210500 } },
  { 0x20, 0x01,
          { 0xEFDB6055, 0x4EB0C8FD, 0x4D66BAD5, 0xA5716F6F,
            0x3315BA06, 0xB5E09122, 0x44A18E71, 0x51E36297,
            0xF137B870, 0x3C7265F6, 0x00C30D5B, 0x295A09AA,
            0xB42B85E7, 0xAC007723, 0x742077A7, 0x4BADCF9B } },
  { 0x20, 0x01,
          { 0xB49E8FA1, 0xB87AED22, 0x86152D27, 0xBEB398AD,
            0xBD48EB80, 0x1D4447DA, 0xB7458BA9, 0xA9E9EF9B,
            0xF7599C6A, 0x203FB309, 0x694A1283, 0xC4875743,
            0xF4E78B62, 0x50BE8206, 0x7BEF5DF7, 0xF92F6B9C } },
  { 0x20, 0x01,
          { 0xD8936EA9, 0x4FDFA7F9, 0x2E23D116, 0xED7C3692,
            0x3E463C40, 0xA5AA5D55, 0xA05A6E11, 0xD22C7D58,
            0x3C0D461D, 0x5D78E74F, 0x88C9121B, 0xECA4CA13,
            0xE12928CB, 0x0167E06D, 0x90E1494E, 0x7CBBCCDA } },
  { 0x20, 0x01,
          { 0xDC4D4AE5, 0x2EA22D30, 0x0F46317D, 0x61B76178,
            0x317CF942, 0xAA617101, 0xB1B646B0, 0x9FB8201C,
            0x31E77E87, 0x0E87682D, 0xAB27674A, 0x1C00EF33,
            0x49676DA0, 0x5E36BB3F, 0x369CB43A, 0xF6E575E8 } },
  { 0x20, 0x01, 
          { 0x472112C6, 0xEBBA21DD, 0x69FAF1B0, 0x06AADA3C,
            0x958968BA, 0xFAF43AF0, 0x8A346D6C, 0x04DAD629,
            0x28C63C70, 0xF49BAA13, 0x57DE5F7C, 0x28841E18,
            0xEA3F594F, 0x8D744A62, 0x57B54FF1, 0x753A4160 } },
  { 0x20, 0x01,
          { 0x865ACF57, 0x0B1CD341, 0x44571AAD, 0x1E351C75,
            0x679AB711, 0x8D923CDC, 0x115DC180, 0xCF5E7435,
            0x94D66EB3, 0x6B643DA7, 0xC71FD3A8, 0xEACD114A,
            0xFE5A4582, 0x101A0A61, 0xDEF929CE, 0xF81307CE } },
  { 0x20, 0x01,
          { 0xEE830EF5, 0xEFEDB52C, 0xD9B5DDE0, 0x11699703,
            0xA59F827F, 0xE7DA769E, 0x9ACF9688, 0xFE6B4EE6,
            0x2D99EFFF, 0xC1F42728, 0x1B33FCE4, 0x2484C32D,
            0x454DEF51, 0x65220E90, 0xD8B53023, 0x10265221 } },
  { 0xc0, 0x01,
          { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 } },
  { 0x40, 0x01,
          { 0x0000004000000401, 0x2020000400000000, 0x2000042000000020, 0x42400888420A0840,
            0x1008008580981891, 0x8240004842020800, 0x4800020A00420200, 0xC200084042420048,
            0x4100000021210004, 0x8844080A80440408, 0x4120000421010000, 0x0420010100210100,
            0x0400010100200000, 0x2000000020200004, 0x8802080A40420208, 0x4020000401010000 } },
  { 0x40, 0x01,
          { 0x9D802FD127A732A1, 0xBFDC94FCF7EDB4F6, 0x50E28C54A198AD0E, 0x09FCDB8FCCC9DDA8,
            0x7ACEC81E5BAA6D25, 0x10C9CBCF5BFEFC27, 0x11A152F2C1A43FCA, 0x6BA77CCFA2D9F407,
            0x0E03AD8E4F36AD96, 0xB405D697E680A2BB, 0x3651B1301374F05D, 0xEC2A3CD28E701034,
            0xD793C96953AA22B3, 0x81B56FC8F78827DD, 0xA5F18C894182A861, 0xF95F620C599E1A7D } },
  { 0x40, 0x01,
          { 0x6D9C774FB118B930, 0x0AD4888256442919, 0xB2625AFA68288616, 0x3F682524B541B12D,
            0x09FB30C77ED1253C, 0xD276B00A56FA3BB2, 0xD1A3ED2B432628E0, 0x59DE47C408703466,
            0x730C85F6CF7CD9B4, 0xD731F331C620402D, 0x664456562656A61E, 0x10F001A72ABF1CCA,
            0xE04F26164B84BCD5, 0xE1CE43EA4AC71790, 0xBE0A7BDA26AB8C3E, 0x083CB972BE746F0D } },
  { 0x40, 0x01,
          { 0x9AE671BAC4106A33, 0x2532A3AF80EB8C24, 0x8807B8748AAF89BB, 0xCCBD275D7AC0180C,
            0x9E3C9A644E2EE2B1, 0x6EF830BF37A17BB2, 0xA56A3F09DA96ABC9, 0x6674A590854EA97D,
            0xD58BFB1A8D2677C5, 0x5696D8DEA26A6D6D, 0x2E973803C96922A4, 0x9C8EC44641A390FD,
            0xABE2F120F069F77A, 0x305FE9E02B725884, 0x1D2A9380316FE1A6, 0x8FA5B15C10F77415 } },
  { 0x40, 0x01,
          { 0xE7BC1BB342393A06, 0x4497F473D8AE5B3A, 0x238B885A51663B54, 0xFCFD9F88948D42A7,
            0x5B6E332077A59C5D, 0xC798AA981789AC8D, 0xF916664458B5AD3F, 0xF7086A16B2407A56,
            0x8DD6CEC45AC62D09, 0x2C217A7DC1AB282C, 0x8AA14855B8A7A065, 0x1BA096650A8E8F6D,
            0x9ECAB9E7A91D59FE, 0xA57F363A65CF10D3, 0xF16FCED7A605DFE9, 0xC02D0A46B23E8C31 } },
  { 0x40, 0x01,
          { 0x2FCA68C9B1691627, 0x59E2B79D4B2A88F8, 0xD44A3CC624C9028F, 0x6295CCEC81F0F5AF,
            0xAFBA11EEC8CE43A4, 0xA6BC58426BDAB6AC, 0xC9FA0754D15A38A6, 0x61B7C093B862D551,
            0xB7A8A66A9227EE06, 0x17BEF1A5F98B7250, 0xCCAA13033F5ADCD3, 0x15CBCEF3A8A993B5,
            0x2E321403DA39690B, 0xD805E663071507B0, 0x6D7EBAA185FF9F07, 0x64071C2C7A0205EA } },
  { 0x40, 0x01,
          { 0xBF643FF50F9B521B, 0xD6ECDEF9B9AC18B0, 0x29C44312EB0ED72A, 0x6AA97E4B4BF39E0A, 
            0xA957D54C2B38DF1B, 0x23E4928A7504F6B8, 0x6CFEE0C2D418DC84, 0x10464EB477E6D548,
            0x18A96DABB8BBC145, 0x406A6EE1C806F1E4, 0xA54BD0A7B7291B4A, 0x27BC2F8593DD77BE,
            0x3BE8FF6116D7AFB0, 0x4D78AEB59B3A9C25, 0x9F03C664A44601DC, 0xDDBE9B34DA020E59 } },
  { 0x40, 0x01,
          { 0xF51507DD9E95189F, 0xAB5E0B1641FAD08F, 0x09B7BF70943B60DE, 0xE35D03636672DACD,
            0x1D013C731A134DCD, 0x850FC95D9CA677C8, 0x48D78D3658CBE8D0, 0x3898A93514FBF49D,
            0x8849E2B60F59D433, 0xA1C7E702A391D4B9, 0xC0057990DE07D3EE, 0x6BBF9A8B0E6CB108,
            0x7DE67998BA91A9CE, 0x68F2B4BC4B8F6A52, 0x4EFE2C5711E64647, 0x27173B06EFB20807 } },
};

void Norx::prgm_copy_state (state_t* s, state_t* d) {
  uint8_t bits, i;
  bits = pgm_read_byte ((uint8_t*)(&(s->bits)));
  d->bits = bits;
  bits &=0x7f;
  for (i=0;i<16;i++) 
    this->prgm_copy_state_word (bits, (void*)(&(s->state[i])), &(d->state[i]));
}

bool Norx::_test_F_one (uint8_t i, state_t* s) {
  char prefix[] = "f    ";
  state_t e;
  
  Serial.print("F test vector ");
  Serial.println(i);
  this->prgm_copy_state((state_t*)&(F_TEST_VECTORS[i]),&e);
  
  for(uint8_t i=0;i<40;i++)
    Serial.print('-');
  Serial.println();

  if (e.bits&0x80) {
    e.bits&=0x7f;
    this->copy_state(&e, s);
  } else
    this->_F (s);
  if (i<10) prefix[1] = 0x20;
  else prefix[1] = (i/10)+0x30;
  prefix[2] = (i%10)+0x30;
  this->dump_state(s,prefix);
  Serial.println();
  this->dump_state(&e, "exp  ");
  return _TEST (this->compare_state(s, &(e)));
}

bool Norx::_test_F (void) {
  uint8_t i, c = 0, len;
  state_t s;
  
  len = sizeof(F_TEST_VECTORS)/sizeof(state_t);
  // calculation loops
  for (i=0; i<len; ++i)
    if (this->_test_F_one(i, &s))
      c++;  
  return _TEST (c==len);
}

bool Norx::_test_init (void) {
  state_t s;
  stw k[4];
  stw n[2];
  uint8_t w;
  uint8_t a = 4;
 
  // 32 bits tests;
  w = 32;
  k[0].b32 = 0x00112233;
  k[1].b32 = 0x44556677;
  k[2].b32 = 0x8899aabb;
  k[3].b32 = 0xccddeeff;
  n[0].b32 = 0xffffffff;
  n[1].b32 = 0xffffffff;
  this->empty_state (w, &s);
  this->_init (&s, w, 4, 1, a, k, n, 0);
  return 1;
}
