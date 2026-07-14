//------------------------------------------------------------------------------
// aes_core.sv
//
// Iterative AES-128 encrypt-only core. A one-cycle start pulse is sampled in
// IDLE on clk rising edge, capturing key_in/plaintext_in and registering the
// initial AddRoundKey. The next KEY_EXPAND cycle computes all ten post-initial
// round keys from the captured key and stores them. ENCRYPT then performs one
// AES round per cycle for ten cycles. ciphertext_out is updated and done pulses
// high for one cycle when the final round result is registered.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module aes_core (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         start,
  input  logic [127:0] key_in,
  input  logic [127:0] plaintext_in,
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

  typedef enum logic [1:0] {
    IDLE,
    KEY_EXPAND,
    ENCRYPT,
    DONE
  } aes_fsm_state_t;

  aes_fsm_state_t state_q;
  aes_fsm_state_t state_d;

  logic [3:0]   round_ctr_q;
  logic [3:0]   round_ctr_d;
  logic [127:0] aes_state_q;
  logic [127:0] aes_state_d;
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
  logic [127:0] round_result_comb;

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

  function automatic logic [127:0] aes_sub_bytes(input logic [127:0] state);
    logic [127:0] result;

    result = '0;
    for (int byte_idx = 0; byte_idx < 16; byte_idx++) begin
      result[127 - (byte_idx * 8) -: 8] =
        aes_sbox_lookup(state[127 - (byte_idx * 8) -: 8]);
    end
    aes_sub_bytes = result;
  endfunction

  function automatic logic [127:0] aes_shift_rows(input logic [127:0] state);
    logic [127:0] result;

    result = '0;
    for (int row = 0; row < 4; row++) begin
      for (int col = 0; col < 4; col++) begin
        result = aes_state_set_byte(
          result,
          row,
          col,
          aes_state_get_byte(state, row, (col + row) % 4)
        );
      end
    end
    aes_shift_rows = result;
  endfunction

  function automatic logic [127:0] aes_mix_columns(input logic [127:0] state);
    logic [127:0] result;
    aes_byte_t    s0;
    aes_byte_t    s1;
    aes_byte_t    s2;
    aes_byte_t    s3;

    result = '0;
    for (int col = 0; col < 4; col++) begin
      s0 = aes_state_get_byte(state, 0, col);
      s1 = aes_state_get_byte(state, 1, col);
      s2 = aes_state_get_byte(state, 2, col);
      s3 = aes_state_get_byte(state, 3, col);

      result = aes_state_set_byte(result, 0, col,
        aes_gmul2(s0) ^ aes_gmul3(s1) ^ s2 ^ s3);
      result = aes_state_set_byte(result, 1, col,
        s0 ^ aes_gmul2(s1) ^ aes_gmul3(s2) ^ s3);
      result = aes_state_set_byte(result, 2, col,
        s0 ^ s1 ^ aes_gmul2(s2) ^ aes_gmul3(s3));
      result = aes_state_set_byte(result, 3, col,
        aes_gmul3(s0) ^ s1 ^ s2 ^ aes_gmul2(s3));
    end
    aes_mix_columns = result;
  endfunction

  function automatic logic [127:0] aes_round(
    input logic [127:0] state,
    input logic [127:0] round_key,
    input logic         final_round
  );
    logic [127:0] after_sub_bytes;
    logic [127:0] after_shift_rows;
    logic [127:0] after_mix_columns;

    after_sub_bytes  = aes_sub_bytes(state);
    after_shift_rows = aes_shift_rows(after_sub_bytes);
    after_mix_columns = final_round ? after_shift_rows :
                                      aes_mix_columns(after_shift_rows);
    aes_round = after_mix_columns ^ round_key;
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
    aes_state_d  = aes_state_q;
    key0_d       = key0_q;
    ciphertext_d = ciphertext_q;
    done_d       = 1'b0;

    temp_word_comb    = 32'h00000000;
    round_result_comb = 128'h00000000000000000000000000000000;

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

    unique case (state_q)
      IDLE: begin
        if (start) begin
          key0_d      = key_in;
          aes_state_d = plaintext_in ^ key_in;
          round_ctr_d = 4'd0;
          state_d     = KEY_EXPAND;
        end
      end

      KEY_EXPAND: begin
        for (int idx = 0; idx < 10; idx++) begin
          round_keys_d[idx] = expanded_round_keys_comb[idx];
        end
        round_ctr_d = 4'd0;
        state_d     = ENCRYPT;
      end

      ENCRYPT: begin
        if (round_ctr_q < 4'd9) begin
          round_result_comb = aes_round(
            aes_state_q,
            round_keys_q[round_ctr_q],
            1'b0
          );
          aes_state_d = round_result_comb;
          round_ctr_d = round_ctr_q + 4'd1;
        end else begin
          round_result_comb = aes_round(
            aes_state_q,
            round_keys_q[9],
            1'b1
          );
          aes_state_d  = round_result_comb;
          ciphertext_d = round_result_comb;
          round_ctr_d  = 4'd0;
          done_d       = 1'b1;
          state_d      = DONE;
        end
      end

      DONE: begin
        state_d = IDLE;
      end

      default: begin
        state_d      = IDLE;
        round_ctr_d  = 4'd0;
        aes_state_d  = 128'h00000000000000000000000000000000;
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
      aes_state_q  <= 128'h00000000000000000000000000000000;
      key0_q       <= 128'h00000000000000000000000000000000;
      ciphertext_q <= 128'h00000000000000000000000000000000;
      done_q       <= 1'b0;
      for (int idx = 0; idx < 10; idx++) begin
        round_keys_q[idx] <= 128'h00000000000000000000000000000000;
      end
    end else begin
      state_q      <= state_d;
      round_ctr_q  <= round_ctr_d;
      aes_state_q  <= aes_state_d;
      key0_q       <= key0_d;
      ciphertext_q <= ciphertext_d;
      done_q       <= done_d;
      for (int idx = 0; idx < 10; idx++) begin
        round_keys_q[idx] <= round_keys_d[idx];
      end
    end
  end

endmodule
