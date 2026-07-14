`timescale 1ns/1ps

module tb_masked_dom32;
  import aes_pkg::*;

  logic clk;
  logic rst_n;

  logic [7:0]  sbox_in0;
  logic [7:0]  sbox_in1;
  logic [31:0] sbox_rand;
  logic [7:0]  sbox_out0;
  logic [7:0]  sbox_out1;

  logic         start;
  logic [127:0] key0_in;
  logic [127:0] key1_in;
  logic [127:0] plaintext_in;
  logic [127:0] state_mask;
  logic [511:0] rand_data_sbox;
  logic [127:0] rand_key_sbox;
  logic [127:0] ciphertext_out;
  logic         done;

  int errors;
  int cycles;

  masked_sbox_dom32 u_sbox (
    .clk(clk),
    .rst_n(rst_n),
    .in0(sbox_in0),
    .in1(sbox_in1),
    .rand_in(sbox_rand),
    .out0(sbox_out0),
    .out1(sbox_out1)
  );

  masked_aes_core_dom32 u_core (
    .clk(clk),
    .rst_n(rst_n),
    .start(start),
    .key0_in(key0_in),
    .key1_in(key1_in),
    .plaintext_in(plaintext_in),
    .state_mask(state_mask),
    .rand_data_sbox(rand_data_sbox),
    .rand_key_sbox(rand_key_sbox),
    .ciphertext_out(ciphertext_out),
    .done(done)
  );

  initial begin
    clk = 1'b0;
    forever #5 clk = ~clk;
  end

  task automatic update_randomness;
    begin
      rand_data_sbox = {rand_data_sbox[510:0],
                        rand_data_sbox[511] ^ rand_data_sbox[507] ^
                        rand_data_sbox[255] ^ rand_data_sbox[0]};
      rand_key_sbox = {rand_key_sbox[126:0],
                       rand_key_sbox[127] ^ rand_key_sbox[95] ^
                       rand_key_sbox[31] ^ rand_key_sbox[0]};
      sbox_rand = {sbox_rand[30:0],
                   sbox_rand[31] ^ sbox_rand[21] ^
                   sbox_rand[1] ^ sbox_rand[0]};
    end
  endtask

  initial begin
    errors = 0;
    rst_n = 1'b0;
    start = 1'b0;
    key0_in = 128'ha5a5a5a5_5a5a5a5a_01234567_89abcdef;
    key1_in = 128'h000102030405060708090a0b0c0d0e0f ^ key0_in;
    plaintext_in = 128'h00112233445566778899aabbccddeeff;
    state_mask = 128'h0123456789abcdeffedcba9876543210;
    rand_data_sbox = 512'h8b7e151628aed2a6abf7158809cf4f3c6bc1bee22e409f96e93d7e117393172a00112233445566778899aabbccddeeff69c4e0d86a7b0430d8cdb78070b4c55a;
    rand_key_sbox = 128'hd6aa74fdd2af72fadaa678f1d6ab76fe;
    sbox_in0 = 8'h00;
    sbox_in1 = 8'h00;
    sbox_rand = 32'hc001d00d;

    repeat (3) @(negedge clk);
    rst_n = 1'b1;

    for (int value = 0; value < 256; value++) begin
      sbox_in0 = 8'h3c ^ value[7:0];
      sbox_in1 = value[7:0] ^ sbox_in0;
      update_randomness();
      @(negedge clk);
      if ((sbox_out0 ^ sbox_out1) !== aes_sbox_lookup(value[7:0])) begin
        $display("FAIL dom32_sbox value=%02h actual=%02h expected=%02h",
                 value[7:0], sbox_out0 ^ sbox_out1,
                 aes_sbox_lookup(value[7:0]));
        errors++;
      end
    end

    @(negedge clk);
    start = 1'b1;
    update_randomness();
    @(negedge clk);
    start = 1'b0;

    cycles = 0;
    while ((done !== 1'b1) && (cycles < 256)) begin
      update_randomness();
      state_mask = {state_mask[126:0],
                    state_mask[127] ^ state_mask[126] ^
                    state_mask[100] ^ state_mask[0]};
      @(negedge clk);
      cycles++;
    end

    if (done !== 1'b1) begin
      $display("FAIL dom32_core done timeout");
      errors++;
    end else if (ciphertext_out !== 128'h69c4e0d86a7b0430d8cdb78070b4c55a) begin
      $display("FAIL dom32_core ciphertext=%032h", ciphertext_out);
      errors++;
    end else begin
      $display("PASS dom32_core latency=%0d ciphertext=%032h",
               cycles, ciphertext_out);
    end

    if (errors == 0) begin
      $display("PASS DOM32 masked checks");
      $finish;
    end

    $display("FAIL DOM32 masked checks errors=%0d", errors);
    $finish(1);
  end
endmodule
