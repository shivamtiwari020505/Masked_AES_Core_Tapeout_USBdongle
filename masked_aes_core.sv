//------------------------------------------------------------------------------
// masked_aes_core.sv
//
// Iterative AES-128 encrypt-only core with a 2-share masked encryption state.
// A one-cycle start pulse captures key_in/plaintext_in and initializes state
// shares as state0=mask and state1=(plaintext_in ^ key_in ^ mask). Round keys
// are expanded as in aes_core.sv. Each round spends one cycle presenting the
// two state shares to 16 masked_sbox instances and one cycle applying the
// linear AES operations in the share domain. done pulses high for one cycle
// when ciphertext_out is valid; ciphertext_out is the final state0 ^ state1.
//
// Security note:
//   This masks the encryption state datapath SubBytes stage. The key schedule
//   remains the unmasked AES-128 key schedule from aes_core.sv, so this is not
//   a complete side-channel-hardened AES implementation for a secret key. A
//   production masked AES must also mask or otherwise protect key expansion,
//   provide sufficient fresh randomness per S-box evaluation, and constrain
//   synthesis/place-and-route to preserve domain separation.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module masked_aes_core (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         start,
  input  logic [127:0] key_in,
  input  logic [127:0] plaintext_in,
  input  logic [127:0] mask,
  output logic [127:0] ciphertext_out,
  output logic         done
);

`ifdef YOSYS
  `include "aes_tables.svh"

  typedef logic [7:0] aes_byte_t;

  localparam logic [2047:0] AES_SBOX_LOCAL = {`AES_SBOX_VALUES};
  localparam logic [79:0]   AES_RCON_LOCAL = {`AES_RCON_VALUES};

  function automatic aes_byte_t aes_sbox_lookup(input aes_byte_t index);
    int unsigned lookup_idx;

    lookup_idx = index;
    aes_sbox_lookup = AES_SBOX_LOCAL >> ((255 - lookup_idx) * 8);
  endfunction

  function automatic aes_byte_t aes_rcon_lookup(input int unsigned round);
    aes_rcon_lookup = AES_RCON_LOCAL >> ((10 - round) * 8);
  endfunction
`else
  import aes_pkg::*;
`endif

  typedef enum logic [2:0] {
    IDLE,
    KEY_EXPAND,
    SUB_BYTES,
    ROUND_LINEAR,
    DONE
  } aes_fsm_state_t;

  aes_fsm_state_t state_q;
  aes_fsm_state_t state_d;

  logic [3:0]   round_ctr_q;
  logic [3:0]   round_ctr_d;
  logic [127:0] state0_q;
  logic [127:0] state0_d;
  logic [127:0] state1_q;
  logic [127:0] state1_d;
  logic [127:0] key0_q;
  logic [127:0] key0_d;
  logic [127:0] ciphertext_q;
  logic [127:0] ciphertext_d;
  logic         done_q;
  logic         done_d;

  logic [127:0] round_keys_q [0:9];
  logic [127:0] round_keys_d [0:9];

  logic [31:0]  key_words_comb [0:43];
  logic [127:0] expanded_round_keys_comb [0:9];
  logic [31:0]  temp_word_comb;

  logic [127:0] sbox_state0;
  logic [127:0] sbox_state1;
  logic [127:0] after_shift0_comb;
  logic [127:0] after_shift1_comb;
  logic [127:0] after_mix0_comb;
  logic [127:0] after_mix1_comb;
  logic [127:0] round_state0_comb;
  logic [127:0] round_state1_comb;

  genvar byte_idx;
  generate
    for (byte_idx = 0; byte_idx < 16; byte_idx++) begin : gen_masked_sboxes
      localparam int BYTE_MSB = 127 - (byte_idx * 8);

      masked_sbox u_masked_sbox (
        .clk     (clk),
        .rst_n   (rst_n),
        .in0     (state0_q[BYTE_MSB -: 8]),
        .in1     (state1_q[BYTE_MSB -: 8]),
        .mask_in (mask[BYTE_MSB -: 8]),
        .out0    (sbox_state0[BYTE_MSB -: 8]),
        .out1    (sbox_state1[BYTE_MSB -: 8])
      );
    end
  endgenerate

  function automatic aes_byte_t aes_state_get_byte(
    input logic [127:0] state,
    input int unsigned  row,
    input int unsigned  col
  );
    aes_state_get_byte = state[127 - (((col * 4) + row) * 8) -: 8];
  endfunction

  function automatic logic [127:0] aes_state_set_byte(
    input logic [127:0] state,
    input int unsigned  row,
    input int unsigned  col,
    input aes_byte_t    value
  );
    aes_state_set_byte = state;
    aes_state_set_byte[127 - (((col * 4) + row) * 8) -: 8] = value;
  endfunction

  function automatic aes_byte_t aes_xtime(input aes_byte_t value);
    aes_xtime = {value[6:0], 1'b0} ^ (8'h1b & {8{value[7]}});
  endfunction

  function automatic aes_byte_t aes_gmul2(input aes_byte_t value);
    aes_gmul2 = aes_xtime(value);
  endfunction

  function automatic aes_byte_t aes_gmul3(input aes_byte_t value);
    aes_gmul3 = aes_xtime(value) ^ value;
  endfunction

  function automatic logic [127:0] aes_shift_rows_share(
    input logic [127:0] state_share
  );
    logic [127:0] result;

    result = '0;
    for (int row = 0; row < 4; row++) begin
      for (int col = 0; col < 4; col++) begin
        result = aes_state_set_byte(
          result,
          row,
          col,
          aes_state_get_byte(state_share, row, (col + row) % 4)
        );
      end
    end
    aes_shift_rows_share = result;
  endfunction

  function automatic logic [127:0] aes_mix_columns_share(
    input logic [127:0] state_share
  );
    logic [127:0] result;
    aes_byte_t    s0;
    aes_byte_t    s1;
    aes_byte_t    s2;
    aes_byte_t    s3;

    result = '0;
    for (int col = 0; col < 4; col++) begin
      s0 = aes_state_get_byte(state_share, 0, col);
      s1 = aes_state_get_byte(state_share, 1, col);
      s2 = aes_state_get_byte(state_share, 2, col);
      s3 = aes_state_get_byte(state_share, 3, col);

      result = aes_state_set_byte(result, 0, col,
        aes_gmul2(s0) ^ aes_gmul3(s1) ^ s2 ^ s3);
      result = aes_state_set_byte(result, 1, col,
        s0 ^ aes_gmul2(s1) ^ aes_gmul3(s2) ^ s3);
      result = aes_state_set_byte(result, 2, col,
        s0 ^ s1 ^ aes_gmul2(s2) ^ aes_gmul3(s3));
      result = aes_state_set_byte(result, 3, col,
        aes_gmul3(s0) ^ s1 ^ s2 ^ aes_gmul2(s3));
    end
    aes_mix_columns_share = result;
  endfunction

  function automatic logic [31:0] aes_key_word(
    input logic [127:0] key,
    input int unsigned  word_idx
  );
    aes_key_word = key[127 - (word_idx * 32) -: 32];
  endfunction

  function automatic logic [31:0] aes_rot_word(input logic [31:0] word);
    aes_rot_word = {word[23:0], word[31:24]};
  endfunction

  function automatic logic [31:0] aes_sub_word(input logic [31:0] word);
    aes_sub_word = {
      aes_sbox_lookup(word[31:24]),
      aes_sbox_lookup(word[23:16]),
      aes_sbox_lookup(word[15:8]),
      aes_sbox_lookup(word[7:0])
    };
  endfunction

  always_comb begin
    ciphertext_out = ciphertext_q;
    done = done_q;

    state_d      = state_q;
    round_ctr_d  = round_ctr_q;
    state0_d     = state0_q;
    state1_d     = state1_q;
    key0_d       = key0_q;
    ciphertext_d = ciphertext_q;
    done_d       = 1'b0;

    temp_word_comb = 32'h00000000;

    for (int idx = 0; idx < 10; idx++) begin
      round_keys_d[idx] = round_keys_q[idx];
      expanded_round_keys_comb[idx] = 128'h00000000000000000000000000000000;
    end

    for (int idx = 0; idx < 44; idx++) begin
      key_words_comb[idx] = 32'h00000000;
    end

    key_words_comb[0] = aes_key_word(key0_q, 0);
    key_words_comb[1] = aes_key_word(key0_q, 1);
    key_words_comb[2] = aes_key_word(key0_q, 2);
    key_words_comb[3] = aes_key_word(key0_q, 3);

    for (int round = 1; round <= 10; round++) begin
      temp_word_comb = aes_sub_word(aes_rot_word(key_words_comb[(round * 4) - 1])) ^
                       {aes_rcon_lookup(round), 24'h000000};

      key_words_comb[round * 4] =
        key_words_comb[(round - 1) * 4] ^ temp_word_comb;
      key_words_comb[(round * 4) + 1] =
        key_words_comb[((round - 1) * 4) + 1] ^ key_words_comb[round * 4];
      key_words_comb[(round * 4) + 2] =
        key_words_comb[((round - 1) * 4) + 2] ^ key_words_comb[(round * 4) + 1];
      key_words_comb[(round * 4) + 3] =
        key_words_comb[((round - 1) * 4) + 3] ^ key_words_comb[(round * 4) + 2];
    end

    for (int round = 0; round < 10; round++) begin
      expanded_round_keys_comb[round] = {
        key_words_comb[(round + 1) * 4],
        key_words_comb[((round + 1) * 4) + 1],
        key_words_comb[((round + 1) * 4) + 2],
        key_words_comb[((round + 1) * 4) + 3]
      };
    end

    after_shift0_comb = aes_shift_rows_share(sbox_state0);
    after_shift1_comb = aes_shift_rows_share(sbox_state1);
    after_mix0_comb   = aes_mix_columns_share(after_shift0_comb);
    after_mix1_comb   = aes_mix_columns_share(after_shift1_comb);
    round_state0_comb = after_mix0_comb;
    round_state1_comb = after_mix1_comb ^ round_keys_q[round_ctr_q];

    unique case (state_q)
      IDLE: begin
        if (start) begin
          key0_d      = key_in;
          state0_d    = mask;
          state1_d    = plaintext_in ^ key_in ^ mask;
          round_ctr_d = 4'd0;
          state_d     = KEY_EXPAND;
        end
      end

      KEY_EXPAND: begin
        for (int idx = 0; idx < 10; idx++) begin
          round_keys_d[idx] = expanded_round_keys_comb[idx];
        end
        round_ctr_d = 4'd0;
        state_d     = SUB_BYTES;
      end

      SUB_BYTES: begin
        state_d = ROUND_LINEAR;
      end

      ROUND_LINEAR: begin
        if (round_ctr_q < 4'd9) begin
          state0_d    = round_state0_comb;
          state1_d    = round_state1_comb;
          round_ctr_d = round_ctr_q + 4'd1;
          state_d     = SUB_BYTES;
        end else begin
          state0_d      = after_shift0_comb;
          state1_d      = after_shift1_comb ^ round_keys_q[9];
          ciphertext_d  = after_shift0_comb ^ after_shift1_comb ^ round_keys_q[9];
          round_ctr_d   = 4'd0;
          done_d        = 1'b1;
          state_d       = DONE;
        end
      end

      DONE: begin
        state_d = IDLE;
      end

      default: begin
        state_d      = IDLE;
        round_ctr_d  = 4'd0;
        state0_d     = 128'h00000000000000000000000000000000;
        state1_d     = 128'h00000000000000000000000000000000;
        key0_d       = 128'h00000000000000000000000000000000;
        ciphertext_d = 128'h00000000000000000000000000000000;
        done_d       = 1'b0;
        for (int idx = 0; idx < 10; idx++) begin
          round_keys_d[idx] = 128'h00000000000000000000000000000000;
        end
      end
    endcase
  end

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      state_q      <= IDLE;
      round_ctr_q  <= 4'd0;
      state0_q     <= 128'h00000000000000000000000000000000;
      state1_q     <= 128'h00000000000000000000000000000000;
      key0_q       <= 128'h00000000000000000000000000000000;
      ciphertext_q <= 128'h00000000000000000000000000000000;
      done_q       <= 1'b0;
      for (int idx = 0; idx < 10; idx++) begin
        round_keys_q[idx] <= 128'h00000000000000000000000000000000;
      end
    end else begin
      state_q      <= state_d;
      round_ctr_q  <= round_ctr_d;
      state0_q     <= state0_d;
      state1_q     <= state1_d;
      key0_q       <= key0_d;
      ciphertext_q <= ciphertext_d;
      done_q       <= done_d;
      for (int idx = 0; idx < 10; idx++) begin
        round_keys_q[idx] <= round_keys_d[idx];
      end
    end
  end

endmodule
