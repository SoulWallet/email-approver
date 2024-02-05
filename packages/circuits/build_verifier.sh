circom -l node_modules EmailApprover.circom -o --r1cs --wasm --sym --c

node EmailApprover_js/generate_witness.js  EmailApprover_js/EmailApprover.wasm  ../tools/input.json witness.wtns

# you can download ptau at https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau

snarkjs groth16 setup EmailApprover.r1cs pot21_final.ptau emailapprover_0000.zkey
snarkjs zkey contribute emailapprover_0000.zkey emailapprover_0001.zkey --name="1st Contributor Name" -v
snarkjs zkey export verificationkey emailapprover_0001.zkey verification_key.json
snarkjs groth16 prove emailapprover_0001.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
snarkjs zkey export verificationkey emailapprover_0001.zkey verification_key.json
snarkjs zkey export solidityverifier emailapprover_0001.zkey Verifier.sol