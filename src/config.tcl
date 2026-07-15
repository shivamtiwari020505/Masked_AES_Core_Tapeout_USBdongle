# Tiny Tapeout TT06 OpenLane configuration.
# Keep project-specific tuning above the generated configuration include.

# Placement and timing targets.
set ::env(PL_TARGET_DENSITY) 0.6
set ::env(CLOCK_PERIOD) "50"
set ::env(PL_RESIZER_HOLD_SLACK_MARGIN) 0.1
set ::env(GLB_RESIZER_HOLD_SLACK_MARGIN) 0.05

# Area/fanout tuning for the serialized masked datapath.
set ::env(MAX_FANOUT_CONSTRAINT) 8
set ::env(SYNTH_STRATEGY) "AREA 0"

# Keep linting enabled.
set ::env(RUN_LINTER) 1
set ::env(LINTER_INCLUDE_PDK_MODELS) 1

# No scan insertion for this side-channel-sensitive masked datapath.
set ::env(RUN_DFT) 0
set ::env(DFT_INSERTION) 0
set ::env(SCAN_INSERTION) 0

# Load the design name, source list, die size, and pin configuration generated
# by tt-support-tools from info.yaml.
set script_dir [file dirname [file normalize [info script]]]
source $::env(DESIGN_DIR)/user_config.tcl

# Tiny Tapeout TT06 flow settings.
set ::env(RUN_KLAYOUT_XOR) 0
set ::env(RUN_KLAYOUT_DRC) 0
set ::env(PL_RESIZER_BUFFER_OUTPUT_PORTS) 0
set ::env(SYNTH_READ_BLACKBOX_LIB) 1

set ::env(TOP_MARGIN_MULT) 1
set ::env(BOTTOM_MARGIN_MULT) 1
set ::env(LEFT_MARGIN_MULT) 6
set ::env(RIGHT_MARGIN_MULT) 6

set ::env(FP_SIZING) absolute
set ::env(PL_BASIC_PLACEMENT) {0}
set ::env(GRT_ALLOW_CONGESTION) "1"
set ::env(FP_IO_HLENGTH) 2
set ::env(FP_IO_VLENGTH) 2

# Use the alternative Efabless decap cell to satisfy LI density.
set ::env(DECAP_CELL) "\
    sky130_fd_sc_hd__decap_3 \
    sky130_fd_sc_hd__decap_4 \
    sky130_fd_sc_hd__decap_6 \
    sky130_fd_sc_hd__decap_8 \
    sky130_ef_sc_hd__decap_12"

set ::env(RUN_CTS) 1
set ::env(CLOCK_PORT) {clk}

# Tiny Tapeout user macros are not standalone cores. Disabling the core power
# ring and limiting routing to met4 prevents forbidden met5 geometry.
set ::env(DESIGN_IS_CORE) 0
set ::env(RT_MAX_LAYER) {met4}
