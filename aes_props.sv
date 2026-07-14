//------------------------------------------------------------------------------
// aes_props.sv
//
// Assertion harness for comparing masked_aes_core against the unmasked aes_core.
// The harness instantiates both cores, captures the unmasked reference output
// when aes_core asserts done, and checks the masked output and recombined
// internal shares when masked_aes_core asserts done.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module aes_props (
  input logic         clk,
  input logic         rst_n,
  input logic         start,
  input logic [127:0] key_in,
  input logic [127:0] plaintext_in,
  input logic [127:0] mask
);

  logic [127:0] ref_ciphertext;
  logic         ref_done;
  logic [127:0] masked_ciphertext;
  logic         masked_done;

  logic [127:0] ref_ciphertext_q;
  logic         ref_valid_q;
  logic         masked_done_seen_q;

  aes_core u_ref (
    .clk            (clk),
    .rst_n          (rst_n),
    .start          (start),
    .key_in         (key_in),
    .plaintext_in   (plaintext_in),
    .ciphertext_out (ref_ciphertext),
    .done           (ref_done)
  );

  masked_aes_core u_masked (
    .clk            (clk),
    .rst_n          (rst_n),
    .start          (start),
    .key_in         (key_in),
    .plaintext_in   (plaintext_in),
    .mask           (mask),
    .ciphertext_out (masked_ciphertext),
    .done           (masked_done)
  );

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      ref_ciphertext_q  <= 128'h00000000000000000000000000000000;
      ref_valid_q       <= 1'b0;
      masked_done_seen_q <= 1'b0;
    end else begin
      if (start) begin
        ref_valid_q        <= 1'b0;
        masked_done_seen_q <= 1'b0;
      end else begin
        if (ref_done) begin
          ref_ciphertext_q <= ref_ciphertext;
          ref_valid_q      <= 1'b1;
        end
        if (masked_done) begin
          masked_done_seen_q <= 1'b1;
        end
      end
    end
  end

`ifdef FORMAL_SVA
  assume_start_is_one_cycle:
    assume property (@(posedge clk) disable iff (!rst_n)
      start |=> !start);

  assert_ref_done_one_cycle:
    assert property (@(posedge clk) disable iff (!rst_n)
      ref_done |=> !ref_done);

  assert_masked_done_one_cycle:
    assert property (@(posedge clk) disable iff (!rst_n)
      masked_done |=> !masked_done);

  assert_masked_output_stable_after_done:
    assert property (@(posedge clk) disable iff (!rst_n)
      masked_done_seen_q && !start |-> $stable(masked_ciphertext));

  assert_masked_ciphertext_matches_reference:
    assert property (@(posedge clk) disable iff (!rst_n)
      masked_done |-> ref_valid_q && (masked_ciphertext == ref_ciphertext_q));

  assert_masked_shares_match_reference_after_done:
    assert property (@(posedge clk) disable iff (!rst_n)
      masked_done |=> ((u_masked.state0_q ^ u_masked.state1_q) == ref_ciphertext_q));
`else
  always_ff @(posedge clk) begin
    if (rst_n) begin
      if ($past(rst_n)) begin
        assert (!(ref_done && $past(ref_done)))
          else $error("aes_props: ref done pulse lasted more than one cycle");
        assert (!(masked_done && $past(masked_done)))
          else $error("aes_props: masked done pulse lasted more than one cycle");
        if ($past(masked_done_seen_q) && !$past(start) && !start) begin
          assert (masked_ciphertext == $past(masked_ciphertext))
            else $error("aes_props: masked output changed after done without start");
        end
        if (masked_done) begin
          assert (ref_valid_q && (masked_ciphertext == ref_ciphertext_q))
            else $error("aes_props: masked ciphertext does not match reference");
        end
        if ($past(masked_done)) begin
          assert ((u_masked.state0_q ^ u_masked.state1_q) == ref_ciphertext_q)
            else $error("aes_props: output shares do not recombine to reference");
        end
      end
    end
  end
`endif

endmodule
