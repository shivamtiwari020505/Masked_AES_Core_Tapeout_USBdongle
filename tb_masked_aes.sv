//------------------------------------------------------------------------------
// tb_masked_aes.sv
//
// File-driven masked AES-128 testbench. Reads vectors.txt as flat $readmemh
// tokens: key, plaintext, expected ciphertext. Each vector is encrypted five
// times with a different 128-bit random mask seed. The bench checks that the
// recombined ciphertext_out from masked_aes_core is independent of the mask and
// matches the expected known-answer ciphertext.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module tb_masked_aes;

  localparam int NUM_VECTORS      = 20;
  localparam int TRIALS_PER_VEC   = 5;
  localparam int TOTAL_TRIALS     = NUM_VECTORS * TRIALS_PER_VEC;
  localparam int WORDS_PER_VEC    = 3;
  localparam int VECTOR_WORDS     = NUM_VECTORS * WORDS_PER_VEC;
  localparam int CLK_PERIOD_NS    = 10;
  localparam int RESET_TIME_NS    = 100;
  localparam int TIMEOUT_CYCLES   = 10000;

  logic         clk;
  logic         rst_n;
  logic         start;
  logic [127:0] key_in;
  logic [127:0] plaintext_in;
  logic [127:0] mask;
  logic [127:0] ciphertext_out;
  logic         done;

  logic [127:0] vector_mem [0:VECTOR_WORDS-1];

  int pass_count;
  int fail_count;

  masked_aes_core dut (
    .clk            (clk),
    .rst_n          (rst_n),
    .start          (start),
    .key_in         (key_in),
    .plaintext_in   (plaintext_in),
    .mask           (mask),
    .ciphertext_out (ciphertext_out),
    .done           (done)
  );

  initial begin
    clk = 1'b0;
    forever #(CLK_PERIOD_NS / 2) clk = ~clk;
  end

  function automatic logic [127:0] random128;
    begin
      random128 = {$urandom(), $urandom(), $urandom(), $urandom()};
    end
  endfunction

  task automatic run_trial(input int vec_idx, input int trial_idx);
    logic [127:0] key;
    logic [127:0] plaintext;
    logic [127:0] expected;
    logic [127:0] mask_start;
    int wait_cycles;
    begin
      key         = vector_mem[(vec_idx * WORDS_PER_VEC) + 0];
      plaintext   = vector_mem[(vec_idx * WORDS_PER_VEC) + 1];
      expected    = vector_mem[(vec_idx * WORDS_PER_VEC) + 2];
      mask_start  = random128();
      wait_cycles = 0;

      key_in       = key;
      plaintext_in = plaintext;
      mask         = mask_start;
      start        = 1'b1;
      @(negedge clk);
      start = 1'b0;

      while ((done !== 1'b1) && (wait_cycles < TIMEOUT_CYCLES)) begin
        mask = random128();
        @(negedge clk);
        wait_cycles++;
      end

      if (done !== 1'b1) begin
        fail_count++;
        $display("MASKED_AES_FAIL vector=%0d trial=%0d reason=timeout cycles=%0d",
                 vec_idx, trial_idx, wait_cycles);
      end else if (ciphertext_out !== expected) begin
        fail_count++;
        $display("MASKED_AES_FAIL vector=%0d trial=%0d reason=ciphertext_mismatch latency=%0d key=%032h plaintext=%032h expected=%032h actual=%032h mask_start=%032h",
                 vec_idx, trial_idx, wait_cycles, key, plaintext, expected,
                 ciphertext_out, mask_start);
      end else begin
        pass_count++;
        $display("MASKED_AES_PASS vector=%0d trial=%0d latency=%0d key=%032h plaintext=%032h expected=%032h actual=%032h mask_start=%032h",
                 vec_idx, trial_idx, wait_cycles, key, plaintext, expected,
                 ciphertext_out, mask_start);
      end

      if (done === 1'b1) begin
        @(negedge clk);
        if (done !== 1'b0) begin
          fail_count++;
          $display("MASKED_AES_FAIL vector=%0d trial=%0d reason=done_not_one_cycle",
                   vec_idx, trial_idx);
        end
      end

      mask = random128();
      @(negedge clk);
    end
  endtask

  initial begin
    $dumpfile("dump_masked.vcd");
    $dumpvars(0, tb_masked_aes);

    pass_count   = 0;
    fail_count   = 0;
    rst_n        = 1'b0;
    start        = 1'b0;
    key_in       = 128'h00000000000000000000000000000000;
    plaintext_in = 128'h00000000000000000000000000000000;
    mask         = 128'h00000000000000000000000000000000;

    $readmemh("vectors.txt", vector_mem);

    #(RESET_TIME_NS);
    @(negedge clk);
    rst_n = 1'b1;
    @(negedge clk);

    for (int idx = 0; idx < NUM_VECTORS; idx++) begin
      for (int trial = 0; trial < TRIALS_PER_VEC; trial++) begin
        run_trial(idx, trial);
      end
    end

    $display("MASKED_AES_SUMMARY passed=%0d total=%0d failed=%0d",
             pass_count, TOTAL_TRIALS, fail_count);

    if ((pass_count == TOTAL_TRIALS) && (fail_count == 0)) begin
      $finish;
    end else begin
      $finish(1);
    end
  end

endmodule
