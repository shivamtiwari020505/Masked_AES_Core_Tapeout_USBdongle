PYTHON   ?= python3
IVERILOG ?= iverilog
VVP      ?= vvp
YOSYS    ?= yosys

RTL      := aes_pkg.sv aes_core.sv
TB       := tb_aes.sv
SIMV     := tb_aes.vvp
VECTORS  := vectors.txt
MASKED_RTL := aes_pkg.sv masked_sbox.sv masked_aes_core.sv
MASKED_TB  := tb_masked_aes.sv
MASKED_SIMV := tb_masked_aes.vvp
MASKED_LOG := masked_sim.log
DOM32_RTL := aes_pkg.sv masked_sbox_dom32.sv masked_aes_core_dom32.sv
DOM32_TB  := tb_masked_dom32.sv
DOM32_SIMV := tb_masked_dom32.vvp
DOM32_LOG := dom32_iverilog.log
SYNTH_DIR := synth
REPORT_DIR := reports

.PHONY: all vectors sim sim_masked check_masking sim_dom32 synth_dirs synth_unmasked synth_masked synth_all clean

all: vectors sim

vectors: $(VECTORS)

$(VECTORS): gen_vectors.py
	$(PYTHON) gen_vectors.py

sim: $(VECTORS)
	$(IVERILOG) -g2012 -DAES_FLAT_TABLES -o $(SIMV) $(RTL) $(TB)
	$(VVP) $(SIMV)

sim_masked: $(VECTORS)
	$(IVERILOG) -g2012 -DAES_FLAT_TABLES -o $(MASKED_SIMV) $(MASKED_RTL) $(MASKED_TB)
	$(VVP) $(MASKED_SIMV) | tee $(MASKED_LOG)

check_masking: sim_masked
	$(PYTHON) check_masking.py $(MASKED_LOG)

sim_dom32:
	$(IVERILOG) -g2012 -DAES_FLAT_TABLES -DMASKING_ASSERTIONS -o $(DOM32_SIMV) $(DOM32_RTL) $(DOM32_TB) 2> $(DOM32_LOG)
	$(VVP) $(DOM32_SIMV)

synth_dirs:
	mkdir -p $(SYNTH_DIR) $(REPORT_DIR)

synth_unmasked: synth_dirs
	$(YOSYS) -l $(REPORT_DIR)/aes_core_yosys.log synth_aes_core.ys

synth_masked: synth_dirs
	$(YOSYS) -l $(REPORT_DIR)/masked_aes_core_yosys.log synth_masked_aes.ys

synth_all: synth_unmasked synth_masked

clean:
	rm -f $(SIMV) $(MASKED_SIMV) $(DOM32_SIMV) dump.vcd dump_masked.vcd $(VECTORS) $(MASKED_LOG) $(DOM32_LOG)
	rm -f $(SYNTH_DIR)/*.v $(SYNTH_DIR)/*.json $(REPORT_DIR)/*.txt $(REPORT_DIR)/*.log
