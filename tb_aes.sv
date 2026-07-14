//------------------------------------------------------------------------------
// tb_aes.sv
//
// File-driven AES-128 testbench. Reads vectors.txt as flat $readmemh tokens:
// key, plaintext, expected ciphertext. Each vector gets a one-cycle start pulse,
// the bench waits for done, compares ciphertext_out, and dumps dump.vcd.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module tb_aes;

  localparam int NUM_VECTORS     = 20;
  localparam int WORDS_PER_VEC   = 3;
  localparam int VECTOR_WORDS    = NUM_VECTORS * WORDS_PER_VEC;
  localparam int CLK_PERIOD_NS   = 10;
  localparam int RESET_TIME_NS   = 100;
  localparam int TIMEOUT_CYCLES  = 10000;

  logic         clk;
  logic         rst_n;
  logic         start;
  logic [127:0] key_in;
  logic [127:0] plaintext_in;
  logic [127:0] ciphertext_out;
  logic         done;

  logic [127:0] vector_mem [0:VECTOR_WORDS-1];

  int pass_count;
  int fail_count;

  aes_core dut (
    .clk            (clk),
    .rst_n          (rst_n),
    .start          (start),
    .key_in         (key_in),
    .plaintext_in   (plaintext_in),
    .ciphertext_out (ciphertext_out),
    .done           (done)
  );

  initial begin
    clk = 1'b0;
    forever #(CLK_PERIOD_NS / 2) clk = ~clk;
  end

  task automatic run_vector(input int vec_idx);
    logic [127:0] key;
    logic [127:0] plaintext;
    logic [127:0] expected;
    int wait_cycles;
    begin
      key         = vector_mem[(vec_idx * WORDS_PER_VEC) + 0];
      plaintext   = vector_mem[(vec_idx * WORDS_PER_VEC) + 1];
      expected    = vector_mem[(vec_idx * WORDS_PER_VEC) + 2];
      wait_cycles = 0;

      key_in       = key;
      plaintext_in = plaintext;
      start        = 1'b1;
      @(negedge clk);
      start = 1'b0;

      while ((done !== 1'b1) && (wait_cycles < TIMEOUT_CYCLES)) begin
        @(negedge clk);
        wait_cycles++;
      end

      if (done !== 1'b1) begin
        fail_count++;
        $display("FAIL vector %0d: timeout after %0d cycles", vec_idx, wait_cycles);
      end else if (ciphertext_out !== expected) begin
        fail_count++;
        $display("FAIL vector %0d: ciphertext mismatch", vec_idx);
        $display("  key       = %032h", key);
        $display("  plaintext = %032h", plaintext);
        $display("  expected  = %032h", expected);
        $display("  actual    = %032h", ciphertext_out);
      end else begin
        pass_count++;
        $display("PASS vector %0d: latency=%0d ciphertext=%032h",
                 vec_idx, wait_cycles, ciphertext_out);
      end

      if (done === 1'b1) begin
        @(negedge clk);
        if (done !== 1'b0) begin
          fail_count++;
          $display("FAIL vector %0d: done did not deassert after one cycle", vec_idx);
        end
      end

      @(negedge clk);
    end
  endtask

  initial begin
    $dumpfile("dump.vcd");
    $dumpvars(0, tb_aes);

    pass_count   = 0;
    fail_count   = 0;
    rst_n        = 1'b0;
    start        = 1'b0;
    key_in       = 128'h00000000000000000000000000000000;
    plaintext_in = 128'h00000000000000000000000000000000;

    $readmemh("vectors.txt", vector_mem);

    #(RESET_TIME_NS);
    @(negedge clk);
    rst_n = 1'b1;
    @(negedge clk);

    for (int idx = 0; idx < NUM_VECTORS; idx++) begin
      run_vector(idx);
    end

    $display("%0d/20 vectors passed", pass_count);

    if ((pass_count == NUM_VECTORS) && (fail_count == 0)) begin
      $finish;
    end else begin
      $finish(1);
    end
  end

endmodule
