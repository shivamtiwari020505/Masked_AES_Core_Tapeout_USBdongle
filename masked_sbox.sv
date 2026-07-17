//------------------------------------------------------------------------------
// masked_sbox.sv
//
// 2-share Boolean masked AES S-box, one-cycle registered output.
//
// Boolean-network origin:
//   The y/t/z straight-line equations are adapted from the Boyar-Peralta
//   depth-16 AES S-box circuit:
//   https://www.nist.gov/publications/depth-16-circuit-aes-s-box
//   This is technical attribution, not a determination of reuse rights. See
//   SOURCE_PROVENANCE.md before including this network in a commercial release.
//
// Masking construction:
//   XOR and affine operations are evaluated independently on each share. Each
//   non-linear AND in the Boolean network is replaced by this randomized
//   two-share functional gadget:
//
//     c0 = (a0 & b0) ^ r
//     c1 = (a0 & b1) ^ (a1 & b0) ^ (a1 & b1) ^ r
//
//   so that c0 ^ c1 = (a0 ^ a1) & (b0 ^ b1). This proves functional
//   recombination only. The cross-products and correction are combinational;
//   this module is not a reviewed or proven Domain-Oriented Masking gadget.
//
// RTL representation note:
//   All internal secret-dependent values are represented as share_t pairs. The
//   RTL never computes in0 ^ in1, the unmasked S-box input, the unmasked S-box
//   output, or out0 ^ out1 inside this module. Linear operations are share-wise;
//   AND operations use share_and(). Therefore, at the RTL signal level, no named
//   intermediate wire is intentionally assigned the unmasked SubBytes input,
//   output, or any unmasked non-linear intermediate. That coding property is
//   not a probing- or glitch-security proof.
//
// Randomness requirements and important limitation:
//   The network contains 32 non-linear operations, but this interface exposes
//   only mask_in[7:0] and expands that byte deterministically. The result is
//   suitable only for functional demonstration. A security-oriented replacement
//   needs a stated masking model, a proven gadget and register placement, fresh
//   independent randomness, implementation review, and leakage assessment.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module masked_sbox (
  input  logic       clk,
  input  logic       rst_n,
  input  logic [7:0] in0,
  input  logic [7:0] in1,
  input  logic [7:0] mask_in,
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

  logic [31:0] dom_rand;
  logic [7:0]  out0_comb;
  logic [7:0]  out1_comb;

`define SHARE_XOR(dst, a, b) \
  begin \
    dst.s0 = a.s0 ^ b.s0; \
    dst.s1 = a.s1 ^ b.s1; \
  end

`define SHARE_AND(dst, a, b, rand_bit) \
  begin \
    dst.s0 = (a.s0 & b.s0) ^ rand_bit; \
    dst.s1 = (a.s0 & b.s1) ^ (a.s1 & b.s0) ^ \
             (a.s1 & b.s1) ^ rand_bit; \
  end

  always_comb begin
    dom_rand = {
      mask_in,
      {mask_in[4:0], mask_in[7:5]} ^ 8'hc3,
      {mask_in[6:0], mask_in[7]} ^ 8'h3c,
      mask_in ^ 8'ha5
    };

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

    `SHARE_XOR(y14, x3, x5)
    `SHARE_XOR(y13, x0, x6)
    `SHARE_XOR(y9, x0, x3)
    `SHARE_XOR(y8, x0, x5)
    `SHARE_XOR(t0, x1, x2)
    `SHARE_XOR(y1, t0, x7)
    `SHARE_XOR(y4, y1, x3)
    `SHARE_XOR(y12, y13, y14)
    `SHARE_XOR(y2, y1, x0)
    `SHARE_XOR(y5, y1, x6)
    `SHARE_XOR(y3, y5, y8)
    `SHARE_XOR(t1, x4, y12)
    `SHARE_XOR(y15, t1, x5)
    `SHARE_XOR(y20, t1, x1)
    `SHARE_XOR(y6, y15, x7)
    `SHARE_XOR(y10, y15, t0)
    `SHARE_XOR(y11, y20, y9)
    `SHARE_XOR(y7, x7, y11)
    `SHARE_XOR(y17, y10, y11)
    `SHARE_XOR(y19, y10, y8)
    `SHARE_XOR(y16, t0, y11)
    `SHARE_XOR(y21, y13, y16)
    `SHARE_XOR(y18, x0, y16)

    `SHARE_AND(t2, y12, y15, dom_rand[0])
    `SHARE_AND(t3, y3, y6, dom_rand[1])
    `SHARE_XOR(t4, t3, t2)
    `SHARE_AND(t5, y4, x7, dom_rand[2])
    `SHARE_XOR(t6, t5, t2)
    `SHARE_AND(t7, y13, y16, dom_rand[3])
    `SHARE_AND(t8, y5, y1, dom_rand[4])
    `SHARE_XOR(t9, t8, t7)
    `SHARE_AND(t10, y2, y7, dom_rand[5])
    `SHARE_XOR(t11, t10, t7)
    `SHARE_AND(t12, y9, y11, dom_rand[6])
    `SHARE_AND(t13, y14, y17, dom_rand[7])
    `SHARE_XOR(t14, t13, t12)
    `SHARE_AND(t15, y8, y10, dom_rand[8])
    `SHARE_XOR(t16, t15, t12)
    `SHARE_XOR(t17, t4, t14)
    `SHARE_XOR(t18, t6, t16)
    `SHARE_XOR(t19, t9, t14)
    `SHARE_XOR(t20, t11, t16)
    `SHARE_XOR(t21, t17, y20)
    `SHARE_XOR(t22, t18, y19)
    `SHARE_XOR(t23, t19, y21)
    `SHARE_XOR(t24, t20, y18)
    `SHARE_XOR(t25, t21, t22)
    `SHARE_AND(t26, t21, t23, dom_rand[9])
    `SHARE_XOR(t27, t24, t26)
    `SHARE_AND(t28, t25, t27, dom_rand[10])
    `SHARE_XOR(t29, t28, t22)
    `SHARE_XOR(t30, t23, t24)
    `SHARE_XOR(t31, t22, t26)
    `SHARE_AND(t32, t31, t30, dom_rand[11])
    `SHARE_XOR(t33, t32, t24)
    `SHARE_XOR(t34, t23, t33)
    `SHARE_XOR(t35, t27, t33)
    `SHARE_AND(t36, t24, t35, dom_rand[12])
    `SHARE_XOR(t37, t36, t34)
    `SHARE_XOR(t38, t27, t36)
    `SHARE_AND(t39, t29, t38, dom_rand[13])
    `SHARE_XOR(t40, t25, t39)
    `SHARE_XOR(t41, t40, t37)
    `SHARE_XOR(t42, t29, t33)
    `SHARE_XOR(t43, t29, t40)
    `SHARE_XOR(t44, t33, t37)
    `SHARE_XOR(t45, t42, t41)

    `SHARE_AND(z0, t44, y15, dom_rand[14])
    `SHARE_AND(z1, t37, y6, dom_rand[15])
    `SHARE_AND(z2, t33, x7, dom_rand[16])
    `SHARE_AND(z3, t43, y16, dom_rand[17])
    `SHARE_AND(z4, t40, y1, dom_rand[18])
    `SHARE_AND(z5, t29, y7, dom_rand[19])
    `SHARE_AND(z6, t42, y11, dom_rand[20])
    `SHARE_AND(z7, t45, y17, dom_rand[21])
    `SHARE_AND(z8, t41, y10, dom_rand[22])
    `SHARE_AND(z9, t44, y12, dom_rand[23])
    `SHARE_AND(z10, t37, y3, dom_rand[24])
    `SHARE_AND(z11, t33, y4, dom_rand[25])
    `SHARE_AND(z12, t43, y13, dom_rand[26])
    `SHARE_AND(z13, t40, y5, dom_rand[27])
    `SHARE_AND(z14, t29, y2, dom_rand[28])
    `SHARE_AND(z15, t42, y9, dom_rand[29])
    `SHARE_AND(z16, t45, y14, dom_rand[30])
    `SHARE_AND(z17, t41, y8, dom_rand[31])

    `SHARE_XOR(tc1, z15, z16)
    `SHARE_XOR(tc2, z10, tc1)
    `SHARE_XOR(tc3, z9, tc2)
    `SHARE_XOR(tc4, z0, z2)
    `SHARE_XOR(tc5, z1, z0)
    `SHARE_XOR(tc6, z3, z4)
    `SHARE_XOR(tc7, z12, tc4)
    `SHARE_XOR(tc8, z7, tc6)
    `SHARE_XOR(tc9, z8, tc7)
    `SHARE_XOR(tc10, tc8, tc9)
    `SHARE_XOR(tc11, tc6, tc5)
    `SHARE_XOR(tc12, z3, z5)
    `SHARE_XOR(tc13, z13, tc1)
    `SHARE_XOR(tc14, tc4, tc12)
    `SHARE_XOR(s3_bit, tc3, tc11)
    `SHARE_XOR(tc16, z6, tc8)
    `SHARE_XOR(tc17, z14, tc10)
    `SHARE_XOR(tc18, tc13, tc14)
    `SHARE_XOR(s7_bit, z12, tc18)
    `SHARE_XOR(tc20, z15, tc16)
    `SHARE_XOR(tc21, tc2, z11)
    `SHARE_XOR(s0_bit, tc3, tc16)
    `SHARE_XOR(s6_bit, tc10, tc18)
    `SHARE_XOR(s4_bit, tc14, s3_bit)
    `SHARE_XOR(s1_bit, s3_bit, tc16)
    `SHARE_XOR(tc26, tc17, tc20)
    `SHARE_XOR(s2_bit, tc26, z17)
    `SHARE_XOR(s5_bit, tc21, tc17)

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
