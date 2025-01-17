#pragma once
// some C macros to implement loop expansion
#define loop1(f) f(0)
#define loop2(f) loop1(f) f(1)
#define loop3(f) loop2(f) f(2)
#define loop4(f) loop3(f) f(3)
#define loop5(f) loop4(f) f(4)
#define loop6(f) loop5(f) f(5)
#define loop7(f) loop6(f) f(6)
#define loop8(f) loop7(f) f(7)
#define loop9(f) loop8(f) f(8)
#define xloop(n,f) loop##n(f)
#define __LOOP(n,f) xloop(n,f) 
// two-level indirection required for macro name expansion.
// __LOOP(4,f) expands to f(0) f(1) f(2) f(3)

#define MUL2_0(f) f(0)
#define MUL2_1(f) f(2)
#define MUL2_2(f) f(4)
#define MUL2_3(f) f(6)
#define MUL2_4(f) f(8)
#define MUL4_0(f) f(0)
#define MUL4_1(f) f(4)
#define MUL4_2(f) f(8)
#define MUL4_3(f) f(12)
#define MUL4_4(f) f(16)
#define xmul(x,y,f) MUL##x##_##y(f)
#define __MUL(x,y,f) xmul(x,y,f)
// some multiplication useful in calculating table rules...

#define ADD1_0(f) f(1)
#define ADD1_1(f) f(2)
#define ADD1_2(f) f(3)
#define ADD1_3(f) f(4)
#define ADD1_4(f) f(5)
#define ADD1_5(f) f(6)
#define ADD1_6(f) f(7)
#define ADD1_7(f) f(8)
#define xadd(x,y,f) ADD##x##_##y(f)
#define __ADD(x,y,f) xadd(x,y,f)
// adding 1 is also useful...

//  #define def_last_word(i, j) hdr.chsh.m_## i ##_## j