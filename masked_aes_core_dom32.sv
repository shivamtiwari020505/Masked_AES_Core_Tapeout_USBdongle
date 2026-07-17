//------------------------------------------------------------------------------
// masked_aes_core_dom32.sv
//
// AES-128 encrypt-only core with a 2-share masked state datapath and a masked
// key schedule. The key is supplied as external Boolean shares key0_in/key1_in
// where key = key0_in ^ key1_in. The initial AES state is also shared without
// forming an unmasked key wire:
//
//   state0 = state_mask ^ key0_in
//   state1 = plaintext_in ^ state_mask ^ key1_in
//
// The core expands post-initial round-key shares using four masked_sbox_dom32
// instances for SubWord, then encrypts using 16 masked_sbox_dom32 instances for
// SubBytes. rand_key_sbox[127:0] must be fresh in each KEY_SUBWORD cycle.
// rand_data_sbox[511:0] must be fresh in each SUB_BYTES cycle. done pulses high
// for one cycle when ciphertext_out = final_state0 ^ final_state1 is valid.
//
// Security note:
//   This is a functional two-share experiment, not an established first-order
//   secure implementation. Its masked_sbox_dom32 dependency uses a combinational
//   randomized gadget without a probing/glitch proof. A production replacement
//   requires a defined security model, reviewed gadget and register structure,
//   verified randomness, implementation controls, and measured leakage evidence.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

(* keep_hierarchy = "yes", dont_touch = "true" *)
module masked_aes_core_dom32 (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         start,
  input  logic [127:0] key0_in,
  input  logic [127:0] key1_in,
  input  logic [127:0] plaintext_in,
  input  logic [127:0] state_mask,
  input  logic [511:0] rand_data_sbox,
  input  logic [127:0] rand_key_sbox,
  output logic [127:0] ciphertext_out,
  output logic         done
);

  import aes_pkg::*;

  typedef enum logic [2:0] {
    IDLE,
    KEY_SUBWORD,
    KEY_UPDATE,
    SUB_BYTES,
    ROUND_LINEAR,
    DONE
  } aes_fsm_state_t;

  aes_fsm_state_t state_q;
  aes_fsm_state_t state_d;

  logic [3:0]   round_ctr_q;
  logic [3:0]   round_ctr_d;
  logic [3:0]   key_round_q;
  logic [3:0]   key_round_d;
  (* keep = "true" *) logic [127:0] state0_q;
  logic [127:0] state0_d;
  (* keep = "true" *) logic [127:0] state1_q;
  logic [127:0] state1_d;
  logic [127:0] ciphertext_q;
  logic [127:0] ciphertext_d;
  logic         done_q;
  logic         done_d;

  (* keep = "true" *) logic [31:0] key_words0_q [0:3];
  logic [31:0] key_words0_d [0:3];
  (* keep = "true" *) logic [31:0] key_words1_q [0:3];
  logic [31:0] key_words1_d [0:3];
  logic [31:0] next_key_words0_comb [0:3];
  logic [31:0] next_key_words1_comb [0:3];

  (* keep = "true" *) logic [127:0] round_keys0_q [0:9];
  logic [127:0] round_keys0_d [0:9];
  (* keep = "true" *) logic [127:0] round_keys1_q [0:9];
  logic [127:0] round_keys1_d [0:9];

  logic [31:0]  key_rot0_comb;
  logic [31:0]  key_rot1_comb;
  logic [31:0]  key_sub0_comb;
  logic [31:0]  key_sub1_comb;
  logic [31:0]  key_temp0_comb;
  logic [31:0]  key_temp1_comb;

  logic [31:0]  key_sbox_out0;
  logic [31:0]  key_sbox_out1;
  logic [127:0] data_sbox_state0;
  logic [127:0] data_sbox_state1;

  logic [127:0] after_shift0_comb;
  logic [127:0] after_shift1_comb;
  logic [127:0] after_mix0_comb;
  logic [127:0] after_mix1_comb;
  logic [127:0] round_state0_comb;
  logic [127:0] round_state1_comb;
  logic [127:0] final_state0_comb;
  logic [127:0] final_state1_comb;

  genvar data_byte_idx;
  generate
    for (data_byte_idx = 0; data_byte_idx < 16; data_byte_idx++) begin : gen_data_sboxes
      localparam int BYTE_MSB = 127 - (data_byte_idx * 8);
      localparam int RAND_MSB = 511 - (data_byte_idx * 32);

      masked_sbox_dom32 u_data_sbox (
        .clk     (clk),
        .rst_n   (rst_n),
        .in0     (state0_q[BYTE_MSB -: 8]),
        .in1     (state1_q[BYTE_MSB -: 8]),
        .rand_in (rand_data_sbox[RAND_MSB -: 32]),
        .out0    (data_sbox_state0[BYTE_MSB -: 8]),
        .out1    (data_sbox_state1[BYTE_MSB -: 8])
      );
    end
  endgenerate

  genvar key_byte_idx;
  generate
    for (key_byte_idx = 0; key_byte_idx < 4; key_byte_idx++) begin : gen_key_sboxes
      localparam int BYTE_MSB = 31 - (key_byte_idx * 8);
      localparam int RAND_MSB = 127 - (key_byte_idx * 32);

      masked_sbox_dom32 u_key_sbox (
        .clk     (clk),
        .rst_n   (rst_n),
        .in0     (key_rot0_comb[BYTE_MSB -: 8]),
        .in1     (key_rot1_comb[BYTE_MSB -: 8]),
        .rand_in (rand_key_sbox[RAND_MSB -: 32]),
        .out0    (key_sbox_out0[BYTE_MSB -: 8]),
        .out1    (key_sbox_out1[BYTE_MSB -: 8])
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

  always_comb begin
    ciphertext_out = ciphertext_q;
    done = done_q;

    state_d      = state_q;
    round_ctr_d  = round_ctr_q;
    key_round_d  = key_round_q;
    state0_d     = state0_q;
    state1_d     = state1_q;
    ciphertext_d = ciphertext_q;
    done_d       = 1'b0;

    for (int idx = 0; idx < 4; idx++) begin
      key_words0_d[idx] = key_words0_q[idx];
      key_words1_d[idx] = key_words1_q[idx];
      next_key_words0_comb[idx] = 32'h00000000;
      next_key_words1_comb[idx] = 32'h00000000;
    end

    for (int idx = 0; idx < 10; idx++) begin
      round_keys0_d[idx] = round_keys0_q[idx];
      round_keys1_d[idx] = round_keys1_q[idx];
    end

    key_rot0_comb = aes_rot_word(key_words0_q[3]);
    key_rot1_comb = aes_rot_word(key_words1_q[3]);
    key_sub0_comb = key_sbox_out0;
    key_sub1_comb = key_sbox_out1;
    key_temp0_comb = key_sub0_comb ^ {aes_rcon_lookup(key_round_q), 24'h000000};
    key_temp1_comb = key_sub1_comb;
    next_key_words0_comb[0] = key_words0_q[0] ^ key_temp0_comb;
    next_key_words1_comb[0] = key_words1_q[0] ^ key_temp1_comb;
    next_key_words0_comb[1] = key_words0_q[1] ^ next_key_words0_comb[0];
    next_key_words1_comb[1] = key_words1_q[1] ^ next_key_words1_comb[0];
    next_key_words0_comb[2] = key_words0_q[2] ^ next_key_words0_comb[1];
    next_key_words1_comb[2] = key_words1_q[2] ^ next_key_words1_comb[1];
    next_key_words0_comb[3] = key_words0_q[3] ^ next_key_words0_comb[2];
    next_key_words1_comb[3] = key_words1_q[3] ^ next_key_words1_comb[2];

    after_shift0_comb = aes_shift_rows_share(data_sbox_state0);
    after_shift1_comb = aes_shift_rows_share(data_sbox_state1);
    after_mix0_comb   = aes_mix_columns_share(after_shift0_comb);
    after_mix1_comb   = aes_mix_columns_share(after_shift1_comb);
    round_state0_comb = after_mix0_comb ^ round_keys0_q[round_ctr_q];
    round_state1_comb = after_mix1_comb ^ round_keys1_q[round_ctr_q];
    final_state0_comb = after_shift0_comb ^ round_keys0_q[9];
    final_state1_comb = after_shift1_comb ^ round_keys1_q[9];

    unique case (state_q)
      IDLE: begin
        if (start) begin
          key_words0_d[0] = aes_key_word(key0_in, 0);
          key_words0_d[1] = aes_key_word(key0_in, 1);
          key_words0_d[2] = aes_key_word(key0_in, 2);
          key_words0_d[3] = aes_key_word(key0_in, 3);
          key_words1_d[0] = aes_key_word(key1_in, 0);
          key_words1_d[1] = aes_key_word(key1_in, 1);
          key_words1_d[2] = aes_key_word(key1_in, 2);
          key_words1_d[3] = aes_key_word(key1_in, 3);

          state0_d     = state_mask ^ key0_in;
          state1_d     = plaintext_in ^ state_mask ^ key1_in;
          round_ctr_d  = 4'd0;
          key_round_d  = 4'd1;
          state_d      = KEY_SUBWORD;
        end
      end

      KEY_SUBWORD: begin
        state_d = KEY_UPDATE;
      end

      KEY_UPDATE: begin
        for (int idx = 0; idx < 4; idx++) begin
          key_words0_d[idx] = next_key_words0_comb[idx];
          key_words1_d[idx] = next_key_words1_comb[idx];
        end

        round_keys0_d[key_round_q - 4'd1] = {
          next_key_words0_comb[0],
          next_key_words0_comb[1],
          next_key_words0_comb[2],
          next_key_words0_comb[3]
        };
        round_keys1_d[key_round_q - 4'd1] = {
          next_key_words1_comb[0],
          next_key_words1_comb[1],
          next_key_words1_comb[2],
          next_key_words1_comb[3]
        };

        if (key_round_q < 4'd10) begin
          key_round_d = key_round_q + 4'd1;
          state_d     = KEY_SUBWORD;
        end else begin
          key_round_d = 4'd0;
          round_ctr_d = 4'd0;
          state_d     = SUB_BYTES;
        end
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
          state0_d      = final_state0_comb;
          state1_d      = final_state1_comb;
          ciphertext_d  = final_state0_comb ^ final_state1_comb;
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
        key_round_d  = 4'd0;
        state0_d     = 128'h00000000000000000000000000000000;
        state1_d     = 128'h00000000000000000000000000000000;
        ciphertext_d = 128'h00000000000000000000000000000000;
        done_d       = 1'b0;
        for (int idx = 0; idx < 4; idx++) begin
          key_words0_d[idx] = 32'h00000000;
          key_words1_d[idx] = 32'h00000000;
        end
        for (int idx = 0; idx < 10; idx++) begin
          round_keys0_d[idx] = 128'h00000000000000000000000000000000;
          round_keys1_d[idx] = 128'h00000000000000000000000000000000;
        end
      end
    endcase
  end

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      state_q      <= IDLE;
      round_ctr_q  <= 4'd0;
      key_round_q  <= 4'd0;
      state0_q     <= 128'h00000000000000000000000000000000;
      state1_q     <= 128'h00000000000000000000000000000000;
      ciphertext_q <= 128'h00000000000000000000000000000000;
      done_q       <= 1'b0;
      for (int idx = 0; idx < 4; idx++) begin
        key_words0_q[idx] <= 32'h00000000;
        key_words1_q[idx] <= 32'h00000000;
      end
      for (int idx = 0; idx < 10; idx++) begin
        round_keys0_q[idx] <= 128'h00000000000000000000000000000000;
        round_keys1_q[idx] <= 128'h00000000000000000000000000000000;
      end
    end else begin
      state_q      <= state_d;
      round_ctr_q  <= round_ctr_d;
      key_round_q  <= key_round_d;
      state0_q     <= state0_d;
      state1_q     <= state1_d;
      ciphertext_q <= ciphertext_d;
      done_q       <= done_d;
      for (int idx = 0; idx < 4; idx++) begin
        key_words0_q[idx] <= key_words0_d[idx];
        key_words1_q[idx] <= key_words1_d[idx];
      end
      for (int idx = 0; idx < 10; idx++) begin
        round_keys0_q[idx] <= round_keys0_d[idx];
        round_keys1_q[idx] <= round_keys1_d[idx];
      end
    end
  end

`ifndef SYNTHESIS
`ifdef MASKING_ASSERTIONS
  logic         prev_data_rand_valid_q;
  logic         prev_key_rand_valid_q;
  logic         prev_state_mask_valid_q;
  logic [511:0] prev_data_rand_q;
  logic [127:0] prev_key_rand_q;
  logic [127:0] prev_state_mask_q;

  always @(posedge clk) begin
    if (!rst_n) begin
      prev_data_rand_valid_q  <= 1'b0;
      prev_key_rand_valid_q   <= 1'b0;
      prev_state_mask_valid_q <= 1'b0;
      prev_data_rand_q        <= 512'h0;
      prev_key_rand_q         <= 128'h0;
      prev_state_mask_q       <= 128'h0;
    end else begin
      if (state_q == SUB_BYTES) begin
        if (rand_data_sbox === 512'h0) begin
          $error("MASKING_ASSERTIONS: rand_data_sbox is all zero during SUB_BYTES");
        end
        if (prev_data_rand_valid_q && (rand_data_sbox === prev_data_rand_q)) begin
          $error("MASKING_ASSERTIONS: rand_data_sbox reused across SUB_BYTES evaluations");
        end
        prev_data_rand_q       <= rand_data_sbox;
        prev_data_rand_valid_q <= 1'b1;
      end

      if (state_q == KEY_SUBWORD) begin
        if (rand_key_sbox === 128'h0) begin
          $error("MASKING_ASSERTIONS: rand_key_sbox is all zero during KEY_SUBWORD");
        end
        if (prev_key_rand_valid_q && (rand_key_sbox === prev_key_rand_q)) begin
          $error("MASKING_ASSERTIONS: rand_key_sbox reused across KEY_SUBWORD evaluations");
        end
        prev_key_rand_q       <= rand_key_sbox;
        prev_key_rand_valid_q <= 1'b1;
      end

      if ((state_q == IDLE) && start) begin
        if (prev_state_mask_valid_q && (state_mask === prev_state_mask_q)) begin
          $error("MASKING_ASSERTIONS: state_mask reused across encryptions");
        end
        prev_state_mask_q       <= state_mask;
        prev_state_mask_valid_q <= 1'b1;
      end
    end
  end
`endif
`endif

endmodule
