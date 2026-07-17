//------------------------------------------------------------------------------
// masked_aes_round_only.sv
//
// TTSKY26c-targeted serialized masked AES datapath.
//
// This top strips the AES-128 key schedule and accepts precomputed round keys
// over an 8-bit serialized interface. It uses one masked_sbox instance reused
// across all state bytes. This is the smaller streamed version: round keys are
// consumed byte-by-byte when AddRoundKey is applied, and no 128-bit round-key
// register is kept.
//
// Port/protocol mapping:
//   ui_in[7:0]  : plaintext bytes and round-key bytes, serialized
//   uo_out[7:0] : ciphertext bytes, serialized
//   uio_in[7:0] : start in WAIT_START, initial state masks in LOAD_TEXT, and
//                 fresh masked_sbox randomness during SBOX_ISSUE
//   uio_out[0]  : done, high for one cycle with the final output byte
//   uio_oe[0]   : enabled only for the done pulse; otherwise uio pins are inputs
//
// Timing:
//   1. After synchronous reset, pulse uio_in[0] for one clock.
//   2. Drive 16 plaintext bytes on ui_in and 16 state-mask bytes on uio_in.
//   3. Drive the initial round key, 16 bytes on ui_in.
//   4. For each AES round, drive 16 fresh S-box randomness bytes on uio_in
//      during SBOX_ISSUE cycles, then drive that round's 16 round-key bytes on
//      ui_in during ADD_ROUND_KEY cycles.
//   5. Read 16 ciphertext bytes from uo_out. done pulses with byte 15.
//
// Bytes are serialized in FIPS-197 column-major state order.
//
// Security note:
//   This is a tapeout feasibility/demo wrapper around the earlier masked_sbox.
//   It still needs true fresh randomness, domain-preserving synthesis/layout,
//   and leakage validation before any production security claim.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module tt_um_shivamtiwari020505_masked_aes (
  input  wire [7:0] ui_in,
  output wire [7:0] uo_out,
  input  wire [7:0] uio_in,
  output wire [7:0] uio_out,
  output wire [7:0] uio_oe,
  input  wire       ena,
  input  wire       clk,
  input  wire       rst_n
);

  typedef enum logic [2:0] {
    ST_WAIT_START,
    ST_LOAD_TEXT,
    ST_ADD_KEY0,
    ST_SBOX_ISSUE,
    ST_SBOX_CAPTURE,
    ST_ADD_ROUND_KEY,
    ST_OUTPUT
  } fsm_state_t;

  fsm_state_t state_q;

  logic [7:0] state0_q [0:15];
  logic [7:0] state1_q [0:15];
  logic [7:0] buf0_q   [0:15];
  logic [7:0] buf1_q   [0:15];

  logic [3:0] byte_ctr_q;
  logic [3:0] round_ctr_q;

  logic [7:0] sbox_in0;
  logic [7:0] sbox_in1;
  logic [7:0] sbox_mask;
  logic [7:0] sbox_out0;
  logic [7:0] sbox_out1;

  logic [3:0] shift_dest_idx_comb;
  logic [3:0] col_base_comb;
  logic [7:0] mix0_byte_comb;
  logic [7:0] mix1_byte_comb;
  logic [7:0] round_byte0_comb;
  logic [7:0] round_byte1_comb;
  logic [7:0] uo_out_comb;
  logic       done_comb;

  masked_sbox u_masked_sbox (
    .clk     (clk),
    .rst_n   (rst_n),
    .in0     (sbox_in0),
    .in1     (sbox_in1),
    .mask_in (sbox_mask),
    .out0    (sbox_out0),
    .out1    (sbox_out1)
  );

  function automatic logic [7:0] aes_xtime(input logic [7:0] value);
    aes_xtime = {value[6:0], 1'b0} ^ (8'h1b & {8{value[7]}});
  endfunction

  function automatic logic [7:0] aes_gmul2(input logic [7:0] value);
    aes_gmul2 = aes_xtime(value);
  endfunction

  function automatic logic [7:0] aes_gmul3(input logic [7:0] value);
    aes_gmul3 = aes_xtime(value) ^ value;
  endfunction

  function automatic logic [3:0] aes_shift_dest_index(
    input logic [3:0] src_idx
  );
    logic [1:0] row;
    logic [1:0] col;
    logic [1:0] dst_col;

    row = src_idx[1:0];
    col = src_idx[3:2];
    case (row)
      2'd0: dst_col = col;
      2'd1: dst_col = col - 2'd1;
      2'd2: dst_col = col - 2'd2;
      default: dst_col = col - 2'd3;
    endcase
    aes_shift_dest_index = {dst_col, row};
  endfunction

  function automatic logic [7:0] aes_mix_column_byte(
    input logic [7:0] s0,
    input logic [7:0] s1,
    input logic [7:0] s2,
    input logic [7:0] s3,
    input logic [1:0] row
  );
    case (row)
      2'd0: aes_mix_column_byte = aes_gmul2(s0) ^ aes_gmul3(s1) ^ s2 ^ s3;
      2'd1: aes_mix_column_byte = s0 ^ aes_gmul2(s1) ^ aes_gmul3(s2) ^ s3;
      2'd2: aes_mix_column_byte = s0 ^ s1 ^ aes_gmul2(s2) ^ aes_gmul3(s3);
      default: aes_mix_column_byte = aes_gmul3(s0) ^ s1 ^ s2 ^ aes_gmul2(s3);
    endcase
  endfunction

  always_comb begin
    shift_dest_idx_comb = aes_shift_dest_index(byte_ctr_q);
    col_base_comb = {byte_ctr_q[3:2], 2'b00};

    sbox_in0 = 8'h00;
    sbox_in1 = 8'h00;
    sbox_mask = 8'h00;
    if (state_q == ST_SBOX_ISSUE) begin
      sbox_in0 = state0_q[byte_ctr_q];
      sbox_in1 = state1_q[byte_ctr_q];
      sbox_mask = uio_in;
    end

    mix0_byte_comb = aes_mix_column_byte(
      buf0_q[col_base_comb],
      buf0_q[col_base_comb + 4'd1],
      buf0_q[col_base_comb + 4'd2],
      buf0_q[col_base_comb + 4'd3],
      byte_ctr_q[1:0]
    );
    mix1_byte_comb = aes_mix_column_byte(
      buf1_q[col_base_comb],
      buf1_q[col_base_comb + 4'd1],
      buf1_q[col_base_comb + 4'd2],
      buf1_q[col_base_comb + 4'd3],
      byte_ctr_q[1:0]
    );

    if (round_ctr_q == 4'd10) begin
      round_byte0_comb = buf0_q[byte_ctr_q];
      round_byte1_comb = buf1_q[byte_ctr_q] ^ ui_in;
    end else begin
      round_byte0_comb = mix0_byte_comb;
      round_byte1_comb = mix1_byte_comb ^ ui_in;
    end

    uo_out_comb = 8'h00;
    if (ena && (state_q == ST_OUTPUT)) begin
      uo_out_comb = state0_q[byte_ctr_q] ^ state1_q[byte_ctr_q];
    end

    done_comb = ena && (state_q == ST_OUTPUT) && (byte_ctr_q == 4'd15);
  end

  assign uo_out  = uo_out_comb;
  assign uio_out = {7'h00, done_comb};
  assign uio_oe  = {7'h00, done_comb};

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      state_q     <= ST_WAIT_START;
      byte_ctr_q  <= 4'h0;
      round_ctr_q <= 4'h0;
      for (int idx = 0; idx < 16; idx++) begin
        state0_q[idx] <= 8'h00;
        state1_q[idx] <= 8'h00;
        buf0_q[idx]   <= 8'h00;
        buf1_q[idx]   <= 8'h00;
      end
    end else begin
      case (state_q)
        ST_WAIT_START: begin
          byte_ctr_q  <= 4'h0;
          round_ctr_q <= 4'h0;
          if (ena && uio_in[0]) begin
            for (int idx = 0; idx < 16; idx++) begin
              state0_q[idx] <= 8'h00;
              state1_q[idx] <= 8'h00;
              buf0_q[idx]   <= 8'h00;
              buf1_q[idx]   <= 8'h00;
            end
            state_q <= ST_LOAD_TEXT;
          end
        end

        ST_LOAD_TEXT: begin
          state0_q[byte_ctr_q] <= uio_in;
          state1_q[byte_ctr_q] <= ui_in ^ uio_in;
          if (byte_ctr_q == 4'd15) begin
            byte_ctr_q <= 4'h0;
            state_q    <= ST_ADD_KEY0;
          end else begin
            byte_ctr_q <= byte_ctr_q + 4'h1;
          end
        end

        ST_ADD_KEY0: begin
          state1_q[byte_ctr_q] <= state1_q[byte_ctr_q] ^ ui_in;
          if (byte_ctr_q == 4'd15) begin
            byte_ctr_q  <= 4'h0;
            round_ctr_q <= 4'd1;
            state_q     <= ST_SBOX_ISSUE;
          end else begin
            byte_ctr_q <= byte_ctr_q + 4'h1;
          end
        end

        ST_SBOX_ISSUE: begin
          state_q <= ST_SBOX_CAPTURE;
        end

        ST_SBOX_CAPTURE: begin
          buf0_q[shift_dest_idx_comb] <= sbox_out0;
          buf1_q[shift_dest_idx_comb] <= sbox_out1;
          if (byte_ctr_q == 4'd15) begin
            byte_ctr_q <= 4'h0;
            state_q    <= ST_ADD_ROUND_KEY;
          end else begin
            byte_ctr_q <= byte_ctr_q + 4'h1;
            state_q    <= ST_SBOX_ISSUE;
          end
        end

        ST_ADD_ROUND_KEY: begin
          state0_q[byte_ctr_q] <= round_byte0_comb;
          state1_q[byte_ctr_q] <= round_byte1_comb;
          if (byte_ctr_q == 4'd15) begin
            byte_ctr_q <= 4'h0;
            if (round_ctr_q == 4'd10) begin
              state_q <= ST_OUTPUT;
            end else begin
              round_ctr_q <= round_ctr_q + 4'h1;
              state_q     <= ST_SBOX_ISSUE;
            end
          end else begin
            byte_ctr_q <= byte_ctr_q + 4'h1;
          end
        end

        ST_OUTPUT: begin
          if (byte_ctr_q == 4'd15) begin
            byte_ctr_q <= 4'h0;
            state_q    <= ST_WAIT_START;
          end else begin
            byte_ctr_q <= byte_ctr_q + 4'h1;
          end
        end

        default: begin
          state_q     <= ST_WAIT_START;
          byte_ctr_q  <= 4'h0;
          round_ctr_q <= 4'h0;
          for (int idx = 0; idx < 16; idx++) begin
            state0_q[idx] <= 8'h00;
            state1_q[idx] <= 8'h00;
            buf0_q[idx]   <= 8'h00;
            buf1_q[idx]   <= 8'h00;
          end
        end
      endcase
    end
  end

endmodule
