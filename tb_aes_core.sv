//------------------------------------------------------------------------------
// tb_aes_core.sv
//
// Self-checking AES-128 encryption testbench. Each test drives key/plaintext,
// pulses start for one cycle, waits for done, checks ciphertext_out on the done
// cycle, and verifies done deasserts on the following cycle.
//------------------------------------------------------------------------------

`timescale 1ns/1ps

module tb_aes_core;

  localparam int CLK_PERIOD_NS = 10;
  localparam int TIMEOUT_CYCLES = 32;

  logic         clk;
  logic         rst_n;
  logic         start;
  logic [127:0] key_in;
  logic [127:0] plaintext_in;
  logic [127:0] ciphertext_out;
  logic         done;

  int tests_run;
  int tests_failed;

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

  task automatic apply_reset;
    begin
      rst_n        = 1'b0;
      start        = 1'b0;
      key_in       = 128'h00000000000000000000000000000000;
      plaintext_in = 128'h00000000000000000000000000000000;

      repeat (3) @(negedge clk);
      rst_n = 1'b1;
      @(negedge clk);
    end
  endtask

  task automatic run_vector(
    input string      test_name,
    input logic [127:0] key,
    input logic [127:0] plaintext,
    input logic [127:0] expected_ciphertext
  );
    int wait_cycles;
    begin
      tests_run++;
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
        tests_failed++;
        $display("FAIL %-24s done timeout after %0d cycles", test_name, wait_cycles);
      end else begin
        if (ciphertext_out !== expected_ciphertext) begin
          tests_failed++;
          $display("FAIL %-24s ciphertext mismatch", test_name);
          $display("  key      = %032h", key);
          $display("  plaintext= %032h", plaintext);
          $display("  expected = %032h", expected_ciphertext);
          $display("  actual   = %032h", ciphertext_out);
        end else begin
          $display("PASS %-24s latency=%0d cycles ciphertext=%032h",
                   test_name, wait_cycles, ciphertext_out);
        end

        @(negedge clk);
        if (done !== 1'b0) begin
          tests_failed++;
          $display("FAIL %-24s done was not a one-cycle pulse", test_name);
        end
      end

      @(negedge clk);
    end
  endtask

  initial begin
    tests_run    = 0;
    tests_failed = 0;

    apply_reset();

    run_vector(
      "FIPS-197 C.1",
      128'h000102030405060708090a0b0c0d0e0f,
      128'h00112233445566778899aabbccddeeff,
      128'h69c4e0d86a7b0430d8cdb78070b4c55a
    );

    run_vector(
      "zero key/plaintext",
      128'h00000000000000000000000000000000,
      128'h00000000000000000000000000000000,
      128'h66e94bd4ef8a2c3b884cfa59ca342b2e
    );

    run_vector(
      "SP800-38A ECB blk0",
      128'h2b7e151628aed2a6abf7158809cf4f3c,
      128'h6bc1bee22e409f96e93d7e117393172a,
      128'h3ad77bb40d7a3660a89ecaf32466ef97
    );

    run_vector(
      "SP800-38A ECB blk1",
      128'h2b7e151628aed2a6abf7158809cf4f3c,
      128'hae2d8a571e03ac9c9eb76fac45af8e51,
      128'hf5d3d58503b9699de785895a96fdbaaf
    );

    run_vector(
      "SP800-38A ECB blk2",
      128'h2b7e151628aed2a6abf7158809cf4f3c,
      128'h30c81c46a35ce411e5fbc1191a0a52ef,
      128'h43b1cd7f598ece23881b00e3ed030688
    );

    run_vector(
      "SP800-38A ECB blk3",
      128'h2b7e151628aed2a6abf7158809cf4f3c,
      128'hf69f2445df4f9b17ad2b417be66c3710,
      128'h7b0c785e27e8ad3f8223207104725dd4
    );

    if (tests_failed == 0) begin
      $display("AES_CORE_TB PASS: %0d/%0d tests passed", tests_run, tests_run);
      $finish;
    end else begin
      $display("AES_CORE_TB FAIL: %0d/%0d tests failed", tests_failed, tests_run);
      $finish(1);
    end
  end

endmodule
