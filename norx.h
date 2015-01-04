#ifndef __norx_h_
#define __norx_h_

#include "Arduino.h"

typedef union {
  uint64_t b64;
  uint32_t b32;
} stw;

typedef struct {
  uint8_t bits;
  uint8_t rounds;
  stw     state[16];
} state_t;

class Norx {
  private :
  uint8_t rounds;
  state_t state;

  // helper functions
  void dump_state_word (uint8_t bits, stw* w);
  void empty_state (uint8_t bits, state_t* s);
  void dump_state (state_t* s, char* prefix);
  void load_state_word_from_hex (uint8_t bits, stw* w, char* hex_str);
  void copy_state_word (uint8_t bits, stw* s, stw* d);
  void copy_state (state_t* s, state_t* d);
  bool compare_state_word (uint8_t bits, stw* wa, stw* wb);
  bool compare_state (state_t* sa, state_t* sb);

  // crypto functions
  void _XOR_32(stw* w, stw* a, stw* b);
  void _XOR_64(stw* w, stw* a, stw* b);
  void _AND_32(stw* w, stw* a, stw* b);
  void _AND_64(stw* w, stw* a, stw* b);
  void _SHL_32(stw* w, stw* a, uint8_t n);
  void _SHL_64(stw* w, stw* a, uint8_t n);
  void _ROR_32(stw* w, stw* a, uint8_t n);
  void _ROR_64(stw* w, stw* a, uint8_t n);
  void _ADX_32(stw* w, stw* a, stw* b);
  void _ADX_64(stw* w, stw* a, stw* b);
  void _XRL_32(stw* w, stw* a, stw* b, uint8_t v);
  void _XRL_64(stw* w, stw* a, stw* b, uint8_t v);
  void __G_32 (stw* wa, stw* wb, stw* wc, stw* wd);
  void __G_64 (stw* wa, stw* wb, stw* wc, stw* wd);
  void _G (state_t* s, uint8_t a, uint8_t b, uint8_t c, uint8_t d);
  void _F (state_t* s);

  void _init (state_t* s, uint8_t w, uint8_t r, uint8_t d, uint8_t a, stw k[4], stw n[2], uint16_t hlen);
  
  // test functions
  bool _test_32 (void);
  bool _test_64 (void);
  void __test_load_a (uint8_t bits, stw* a);
  bool _test_load_state_word_from_hex (uint8_t bits);
  void __test_load_a_b (uint8_t bits, stw* a, stw* b);
  bool _test_XOR (uint8_t bits);
  bool _test_AND (uint8_t bits);
  bool _test_SHL (uint8_t bits);
  bool _test_ROR (uint8_t bits);
  bool _test_ADX (uint8_t bits);
  bool _test_XRL (uint8_t bits);
  void prgm_copy_state_word (uint8_t bits, void* s, stw* d);
  bool _test_G_one (uint8_t bits, uint8_t idx);
  bool _test_G (uint8_t bits);
  void prgm_copy_state (state_t* s, state_t* d);
  bool _test_F_one (uint8_t i, state_t* s);
  bool _test_F ();
  bool _test_init (void);
  //
  
  public :
    Norx (void);
    void begin (uint8_t rounds);
    bool test (void);
};

#endif
