set ::env(DESIGN_NAME) tt_um_masked_aes_round_only
set ::env(VERILOG_FILES) "\
    $::env(DESIGN_DIR)/src/masked_sbox.sv \
    $::env(DESIGN_DIR)/src/masked_aes_round_only.sv"

set ::env(CLOCK_PORT) "clk"
set ::env(CLOCK_PERIOD) "50"

set ::env(MAX_FANOUT_CONSTRAINT) 8
set ::env(SYNTH_MAX_FANOUT) 8
set ::env(SYNTH_STRATEGY) "AREA 0"

# No scan insertion for this side-channel-sensitive masked datapath.
set ::env(RUN_DFT) 0
set ::env(DFT_INSERTION) 0
set ::env(SCAN_INSERTION) 0
