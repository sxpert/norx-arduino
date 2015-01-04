
#include "norx.h"

Norx norx;

void setup () {
  Serial.begin (9600);
  Serial.println ("Norx testbed");
  norx.test();
}

void loop () {
  char c;
  c = read_char ();
}

int read_char () {
  int c;
  do {
    c = Serial.read();
  } while (c==-1);
  return c;
}


