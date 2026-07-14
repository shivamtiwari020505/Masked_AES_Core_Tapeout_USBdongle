# Generic masking-preservation constraints.
# Adapt command names and patterns to your synthesis/place-and-route tool.

# Preserve masked S-box module boundaries.
set_dont_touch [get_cells -hierarchical *masked_sbox_dom32*]
set_dont_touch [get_cells -hierarchical *masked_aes_core_dom32*]

# Preserve the share state and key-share storage. Tool support for wildcarded
# hierarchical net/register matching varies; review resolved object lists.
set_dont_touch [get_cells -hierarchical *state0_q*]
set_dont_touch [get_cells -hierarchical *state1_q*]
set_dont_touch [get_cells -hierarchical *key_words0_q*]
set_dont_touch [get_cells -hierarchical *key_words1_q*]
set_dont_touch [get_cells -hierarchical *round_keys0_q*]
set_dont_touch [get_cells -hierarchical *round_keys1_q*]

# Disable cross-boundary optimizations that may merge/share logic cones between
# masking domains. Replace with the equivalent controls for your tool.
set_boundary_optimization [get_cells -hierarchical *masked_sbox_dom32*] false

# After synthesis, explicitly inspect resolved objects and netlist structure.
# In particular, search for XOR/recombination of share-0 and share-1 nets before
# the intentional final ciphertext recombination.
