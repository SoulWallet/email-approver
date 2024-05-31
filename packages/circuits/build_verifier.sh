circom -l node_modules EmailApprover.circom --r1cs --wasm;
# https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau

snarkjs groth16 setup EmailApprover.r1cs powersOfTau28_hez_final_22.ptau emailapprover_0000.zkey
snarkjs zkey contribute emailapprover_0000.zkey emailapprover_0001.zkey --name="1st Contributor Name" -v
# snarkjs zkey contribute emailapprover_0001.zkey emailapprover_0002.zkey --name="2nd Contributor Name" -v
# ...

snarkjs zkey export solidityverifier emailapprover_0001.zkey Verifier.sol
# Export the verification key
snarkjs zkey export verificationkey emailapprover_0001.zkey verification_key.json

# witness
node EmailApprover_js/generate_witness.js EmailApprover_js/EmailApprover.wasm ../tools/input.json witness.wtns
# Generating a Proof
snarkjs groth16 prove emailapprover_0001.zkey witness.wtns proof.json public.json
# Verifying the Proof
snarkjs groth16 verify verification_key.json public.json proof.json
# 
snarkjs generatecall
