//------------------------------------------------------------------------------
// masked_sbox_dom32.sv
//
// 2-share Boolean masked AES S-box, one-cycle registered output.
//
// Scheme used:
//   This module uses a DOM-style Boolean masking implementation of the AES S-box
//   Boolean network. XOR and affine operations are evaluated independently on
//   each share. Each non-linear AND in the S-box network is replaced by a
//   2-share randomized DOM AND:
//
//     c0 = (a0 & b0) ^ r
//     c1 = (a0 & b1) ^ (a1 & b0) ^ (a1 & b1) ^ r
//
//   so that c0 ^ c1 = (a0 ^ a1) & (b0 ^ b1). DOM-style masking is used here
//   because it maps cleanly onto a Boolean S-box network and makes it explicit
//   where every non-linear operation consumes randomness. A composite-field
//   masked S-box is usually smaller, but it is easier to accidentally introduce
//   an unmasked recombination when writing it from scratch.
//
// Wires claimed not to carry unmasked SubBytes secrets:
//   All internal secret-dependent values are represented as share_t pairs. The
//   RTL never computes in0 ^ in1, the unmasked S-box input, the unmasked S-box
//   output, or out0 ^ out1 inside this module. Linear operations are share-wise;
//   AND operations use share_and(). Therefore, at the RTL signal level, no named
//   intermediate wire is intentionally assigned the unmasked SubBytes input,
//   output, or any unmasked non-linear intermediate.
//
// Randomness requirements:
//   Strict first-order DOM security for this 32-AND S-box network requires 32
//   independent fresh random bits per S-box evaluation, and the S-box inputs
//   must be stable across the clock edge capturing the outputs. rand_in[31:0]
//   must come from an external TRNG/DRBG or randomness distribution network and
//   must be fresh for every byte and every SubBytes/key-schedule S-box
//   evaluation. Reusing rand_in across bytes, rounds, encryptions, or key
//   expansion SubWord operations invalidates the DOM security assumption.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

(* keep_hierarchy = "yes", dont_touch = "true" *)
module masked_sbox_dom32 (
  input  logic       clk,
  input  logic       rst_n,
  input  logic [7:0] in0,
  input  logic [7:0] in1,
  input  logic [31:0] rand_in,
  output logic [7:0] out0,
  output logic [7:0] out1
);

  typedef struct packed {
    logic s0;
    logic s1;
  } share_t;

  share_t x0;
  share_t x1;
  share_t x2;
  share_t x3;
  share_t x4;
  share_t x5;
  share_t x6;
  share_t x7;

  share_t y1;
  share_t y2;
  share_t y3;
  share_t y4;
  share_t y5;
  share_t y6;
  share_t y7;
  share_t y8;
  share_t y9;
  share_t y10;
  share_t y11;
  share_t y12;
  share_t y13;
  share_t y14;
  share_t y15;
  share_t y16;
  share_t y17;
  share_t y18;
  share_t y19;
  share_t y20;
  share_t y21;

  share_t t0;
  share_t t1;
  share_t t2;
  share_t t3;
  share_t t4;
  share_t t5;
  share_t t6;
  share_t t7;
  share_t t8;
  share_t t9;
  share_t t10;
  share_t t11;
  share_t t12;
  share_t t13;
  share_t t14;
  share_t t15;
  share_t t16;
  share_t t17;
  share_t t18;
  share_t t19;
  share_t t20;
  share_t t21;
  share_t t22;
  share_t t23;
  share_t t24;
  share_t t25;
  share_t t26;
  share_t t27;
  share_t t28;
  share_t t29;
  share_t t30;
  share_t t31;
  share_t t32;
  share_t t33;
  share_t t34;
  share_t t35;
  share_t t36;
  share_t t37;
  share_t t38;
  share_t t39;
  share_t t40;
  share_t t41;
  share_t t42;
  share_t t43;
  share_t t44;
  share_t t45;

  share_t z0;
  share_t z1;
  share_t z2;
  share_t z3;
  share_t z4;
  share_t z5;
  share_t z6;
  share_t z7;
  share_t z8;
  share_t z9;
  share_t z10;
  share_t z11;
  share_t z12;
  share_t z13;
  share_t z14;
  share_t z15;
  share_t z16;
  share_t z17;

  share_t tc1;
  share_t tc2;
  share_t tc3;
  share_t tc4;
  share_t tc5;
  share_t tc6;
  share_t tc7;
  share_t tc8;
  share_t tc9;
  share_t tc10;
  share_t tc11;
  share_t tc12;
  share_t tc13;
  share_t tc14;
  share_t tc16;
  share_t tc17;
  share_t tc18;
  share_t tc20;
  share_t tc21;
  share_t tc26;

  share_t s0_bit;
  share_t s1_bit;
  share_t s2_bit;
  share_t s3_bit;
  share_t s4_bit;
  share_t s5_bit;
  share_t s6_bit;
  share_t s7_bit;

  (* keep = "true" *) logic [31:0] dom_rand;
  (* keep = "true" *) logic [7:0]  out0_comb;
  (* keep = "true" *) logic [7:0]  out1_comb;

  function automatic share_t share_xor(input share_t a, input share_t b);
    share_xor.s0 = a.s0 ^ b.s0;
    share_xor.s1 = a.s1 ^ b.s1;
  endfunction

  function automatic share_t share_and(
    input share_t a,
    input share_t b,
    input logic   rand_bit
  );
    share_and.s0 = (a.s0 & b.s0) ^ rand_bit;
    share_and.s1 = (a.s0 & b.s1) ^ (a.s1 & b.s0) ^
                   (a.s1 & b.s1) ^ rand_bit;
  endfunction

  always_comb begin
    dom_rand = rand_in;

    x0.s0 = in0[7];
    x0.s1 = in1[7];
    x1.s0 = in0[6];
    x1.s1 = in1[6];
    x2.s0 = in0[5];
    x2.s1 = in1[5];
    x3.s0 = in0[4];
    x3.s1 = in1[4];
    x4.s0 = in0[3];
    x4.s1 = in1[3];
    x5.s0 = in0[2];
    x5.s1 = in1[2];
    x6.s0 = in0[1];
    x6.s1 = in1[1];
    x7.s0 = in0[0];
    x7.s1 = in1[0];

    y14 = share_xor(x3, x5);
    y13 = share_xor(x0, x6);
    y9  = share_xor(x0, x3);
    y8  = share_xor(x0, x5);
    t0  = share_xor(x1, x2);
    y1  = share_xor(t0, x7);
    y4  = share_xor(y1, x3);
    y12 = share_xor(y13, y14);
    y2  = share_xor(y1, x0);
    y5  = share_xor(y1, x6);
    y3  = share_xor(y5, y8);
    t1  = share_xor(x4, y12);
    y15 = share_xor(t1, x5);
    y20 = share_xor(t1, x1);
    y6  = share_xor(y15, x7);
    y10 = share_xor(y15, t0);
    y11 = share_xor(y20, y9);
    y7  = share_xor(x7, y11);
    y17 = share_xor(y10, y11);
    y19 = share_xor(y10, y8);
    y16 = share_xor(t0, y11);
    y21 = share_xor(y13, y16);
    y18 = share_xor(x0, y16);

    t2  = share_and(y12, y15, dom_rand[0]);
    t3  = share_and(y3, y6, dom_rand[1]);
    t4  = share_xor(t3, t2);
    t5  = share_and(y4, x7, dom_rand[2]);
    t6  = share_xor(t5, t2);
    t7  = share_and(y13, y16, dom_rand[3]);
    t8  = share_and(y5, y1, dom_rand[4]);
    t9  = share_xor(t8, t7);
    t10 = share_and(y2, y7, dom_rand[5]);
    t11 = share_xor(t10, t7);
    t12 = share_and(y9, y11, dom_rand[6]);
    t13 = share_and(y14, y17, dom_rand[7]);
    t14 = share_xor(t13, t12);
    t15 = share_and(y8, y10, dom_rand[8]);
    t16 = share_xor(t15, t12);
    t17 = share_xor(t4, t14);
    t18 = share_xor(t6, t16);
    t19 = share_xor(t9, t14);
    t20 = share_xor(t11, t16);
    t21 = share_xor(t17, y20);
    t22 = share_xor(t18, y19);
    t23 = share_xor(t19, y21);
    t24 = share_xor(t20, y18);
    t25 = share_xor(t21, t22);
    t26 = share_and(t21, t23, dom_rand[9]);
    t27 = share_xor(t24, t26);
    t28 = share_and(t25, t27, dom_rand[10]);
    t29 = share_xor(t28, t22);
    t30 = share_xor(t23, t24);
    t31 = share_xor(t22, t26);
    t32 = share_and(t31, t30, dom_rand[11]);
    t33 = share_xor(t32, t24);
    t34 = share_xor(t23, t33);
    t35 = share_xor(t27, t33);
    t36 = share_and(t24, t35, dom_rand[12]);
    t37 = share_xor(t36, t34);
    t38 = share_xor(t27, t36);
    t39 = share_and(t29, t38, dom_rand[13]);
    t40 = share_xor(t25, t39);
    t41 = share_xor(t40, t37);
    t42 = share_xor(t29, t33);
    t43 = share_xor(t29, t40);
    t44 = share_xor(t33, t37);
    t45 = share_xor(t42, t41);

    z0  = share_and(t44, y15, dom_rand[14]);
    z1  = share_and(t37, y6, dom_rand[15]);
    z2  = share_and(t33, x7, dom_rand[16]);
    z3  = share_and(t43, y16, dom_rand[17]);
    z4  = share_and(t40, y1, dom_rand[18]);
    z5  = share_and(t29, y7, dom_rand[19]);
    z6  = share_and(t42, y11, dom_rand[20]);
    z7  = share_and(t45, y17, dom_rand[21]);
    z8  = share_and(t41, y10, dom_rand[22]);
    z9  = share_and(t44, y12, dom_rand[23]);
    z10 = share_and(t37, y3, dom_rand[24]);
    z11 = share_and(t33, y4, dom_rand[25]);
    z12 = share_and(t43, y13, dom_rand[26]);
    z13 = share_and(t40, y5, dom_rand[27]);
    z14 = share_and(t29, y2, dom_rand[28]);
    z15 = share_and(t42, y9, dom_rand[29]);
    z16 = share_and(t45, y14, dom_rand[30]);
    z17 = share_and(t41, y8, dom_rand[31]);

    tc1    = share_xor(z15, z16);
    tc2    = share_xor(z10, tc1);
    tc3    = share_xor(z9, tc2);
    tc4    = share_xor(z0, z2);
    tc5    = share_xor(z1, z0);
    tc6    = share_xor(z3, z4);
    tc7    = share_xor(z12, tc4);
    tc8    = share_xor(z7, tc6);
    tc9    = share_xor(z8, tc7);
    tc10   = share_xor(tc8, tc9);
    tc11   = share_xor(tc6, tc5);
    tc12   = share_xor(z3, z5);
    tc13   = share_xor(z13, tc1);
    tc14   = share_xor(tc4, tc12);
    s3_bit = share_xor(tc3, tc11);
    tc16   = share_xor(z6, tc8);
    tc17   = share_xor(z14, tc10);
    tc18   = share_xor(tc13, tc14);
    s7_bit = share_xor(z12, tc18);
    tc20   = share_xor(z15, tc16);
    tc21   = share_xor(tc2, z11);
    s0_bit = share_xor(tc3, tc16);
    s6_bit = share_xor(tc10, tc18);
    s4_bit = share_xor(tc14, s3_bit);
    s1_bit = share_xor(s3_bit, tc16);
    tc26   = share_xor(tc17, tc20);
    s2_bit = share_xor(tc26, z17);
    s5_bit = share_xor(tc21, tc17);

    out0_comb = {
      s0_bit.s0,
      s1_bit.s0,
      s2_bit.s0,
      s3_bit.s0,
      s4_bit.s0,
      s5_bit.s0,
      s6_bit.s0,
      s7_bit.s0
    };
    out1_comb = {
      s0_bit.s1,
      s1_bit.s1,
      s2_bit.s1,
      s3_bit.s1,
      s4_bit.s1,
      s5_bit.s1,
      s6_bit.s1,
      s7_bit.s1
    } ^ 8'h63;
  end

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      out0 <= 8'h00;
      out1 <= 8'h00;
    end else begin
      out0 <= out0_comb;
      out1 <= out1_comb;
    end
  end

endmodule
