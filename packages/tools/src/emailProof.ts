import { readFileSync, existsSync, mkdirSync, rm, writeFileSync } from "fs";
import { join } from "path";
import { generateEmailVerifierInputs } from "@zk-email/helpers";
import { Groth16Proof, PublicSignals, groth16 } from "snarkjs";
import { packBytesIntoNBytes } from "@zk-email/helpers";
import { poseidon } from "@iden3/js-crypto";
import { exec } from "child_process";

export type IEmailApproverCircuitInputs = {
    email_header: string[];
    email_header_length: string;
    pubkey: string[];
    signature: string[];
    sender_email_idx: string;
    sender_email_commitment_rand: string;
    sender_domain_idx: string;
    subject_idx: string;
};

export interface IEmailProof {
    proof: bigint[];
    pubkeyHash: bigint;
    senderDomainHash: bigint;
    senderCommitment: bigint;
    controlAddress: string;
    approvedHash: string;
}

export class EmailProof {
    private _file_wasm: string;
    private _file_zkey: string;
    private vKey;
    private _rapidsnarkProverBin: string | undefined;
    private generateWitnessJsDir: string;

    private _tmpDir: string;

    /**
     * Creates an instance of EmailProof.
     * @param {string} file_wasm the path to the file EmailApprover.wasm
     * @param {string} file_zkey the path to the file emailapprover_final.zkey
     * @param {string} file_vkey the path to the file verification_key.json
     * @param {string} [rapidsnarkProverBin] the path to the file `rapidsnark-xxx-v0.0.2/bin/prover`, if set, will use rapidsnark to generate proof. download from `https://github.com/iden3/rapidsnark/releases/`
     * @memberof EmailProof
     */
    constructor(
        file_wasm: string,
        file_zkey: string,
        file_vkey: string,
        rapidsnarkProverBin?: string
    ) {
        this.vKey = JSON.parse(readFileSync(file_vkey).toString("utf-8"));
        // check if file_wasm and file_zkey exist
        if (!file_wasm || !file_zkey) {
            throw new Error("The file_wasm and file_zkey are required");
        }
        if (!file_wasm.endsWith(".wasm") || !file_zkey.endsWith(".zkey")) {
            throw new Error(
                "The file_wasm must be a .wasm file and the file_zkey must be a .zkey file"
            );
        }
        if (!existsSync(file_wasm) || !existsSync(file_zkey)) {
            throw new Error("The file_wasm and file_zkey must exist");
        }
        if (rapidsnarkProverBin && existsSync(rapidsnarkProverBin)) {
            this._rapidsnarkProverBin = rapidsnarkProverBin;
            console.log("Using rapidsnark to generate proof");
        } else {
            this._rapidsnarkProverBin = undefined;
            console.log("Using snarkjs to generate proof");
        }

        this._file_wasm = file_wasm;
        this._file_zkey = file_zkey;

        this._tmpDir = join(__dirname, "..", ".tmp");
        if (!existsSync(this._tmpDir)) {
            mkdirSync(this._tmpDir);
        }

        // check if generateWitness exists
        this.generateWitnessJsDir = join(__dirname, "..", "generateWitness");
        if (!existsSync(this.generateWitnessJsDir)) {
            throw new Error("The generateWitness directory does not exist");
        }
        if (!existsSync(join(this.generateWitnessJsDir, "generate_witness.js"))) {
            throw new Error("The generate_witness.js does not exist");
        }
        if (!existsSync(join(this.generateWitnessJsDir, "witness_calculator.js"))) {
            throw new Error("The witness_calculator.js does not exist");
        }
    }

    /**
     * generate email address commitment
     *
     * @static
     * @param {string} emailAddr email address ( Case sensitive )
     * @param {bigint} sender_email_commitment_rand random number
     * @return {*}  {bigint}
     * @memberof EmailProof
     */
    public static emailAddrCommit(
        emailAddr: string,
        sender_email_commitment_rand: bigint
    ): bigint {
        /*
                           template EmailAddrCommit(num_ints) {
                               signal input rand;
                               signal input email_addr_ints[num_ints];
                               signal output commit;
                               component poseidon = Poseidon(1+num_ints);
                               poseidon.inputs[0] <== rand;
                               for(var i=0; i<num_ints; i++) {
                                   poseidon.inputs[1+i] <== email_addr_ints[i];
                               }
                               commit <== poseidon.out;
                           }
                       */

        // @zk-email/circuits/utils/constants.circom
        const EMAIL_ADDR_MAX_BYTES = 256;
        const MAX_BYTES_IN_FIELD = 31;
        if (emailAddr.length > EMAIL_ADDR_MAX_BYTES) {
            throw new Error("Email address is too long");
        }
        const _sender_email_addr_ints = packBytesIntoNBytes(
            emailAddr,
            MAX_BYTES_IN_FIELD
        );
        const sender_email_addr_ints: bigint[] = [];
        for (
            let index = 0;
            index <
            Math.ceil(
                EMAIL_ADDR_MAX_BYTES / MAX_BYTES_IN_FIELD
            ) /*computeIntChunkLength()*/;
            index++
        ) {
            if (index < _sender_email_addr_ints.length) {
                sender_email_addr_ints[index] = BigInt(_sender_email_addr_ints[index]);
            } else {
                sender_email_addr_ints[index] = BigInt(0);
            }
        }
        const poseidonInputs = [
            sender_email_commitment_rand,
            ...sender_email_addr_ints,
        ];
        const out = poseidon.hash(poseidonInputs);
        return out;
    }

    public static emailDomainHash(emailDomain: string): bigint {
        const DOMAIN_MAX_BYTES = 255;
        const MAX_BYTES_IN_FIELD = 31;
        const _email_domain_ints = packBytesIntoNBytes(
            emailDomain,
            MAX_BYTES_IN_FIELD
        );
        const email_domain_ints: bigint[] = [];
        for (
            let index = 0;
            index <
            Math.ceil(
                DOMAIN_MAX_BYTES / MAX_BYTES_IN_FIELD
            ) /*computeIntChunkLength()*/;
            index++
        ) {
            if (index < _email_domain_ints.length) {
                email_domain_ints[index] = BigInt(_email_domain_ints[index]);
            } else {
                email_domain_ints[index] = BigInt(0);
            }
        }
        const out = poseidon.hash(email_domain_ints);
        return out;
    }

    public static async dkimPublicKeyHash(rawEmail: string): Promise<any | null> {
        /*
                     https://zkrepl.dev/?gist=43ce7dce2466c63812f6efec5b13aa73
                     pragma circom 2.1.6;
                     include "circomlib/poseidon.circom";
                     template PubkeyHasher(n, k) {
                         signal input pubkey[k];
                         signal output pubkey_hash;
                         var k2_chunked_size = k >> 1;
                         if(k % 2 == 1) {
                             k2_chunked_size += 1;
                         }
                         log("k2_chunked_size", k2_chunked_size);
                         signal pubkey_hash_input[k2_chunked_size];
                         for(var i = 0; i < k2_chunked_size; i++) {
                             if(i==k2_chunked_size-1 && k2_chunked_size % 2 == 1) {
                                 log(i);
                                 pubkey_hash_input[i] <== pubkey[2*i];
                             } else {
                                 log(i);
                                 pubkey_hash_input[i] <== pubkey[2*i] + (1<<n) * pubkey[2*i+1];
                             }
                         }
                         pubkey_hash <== Poseidon(k2_chunked_size)(pubkey_hash_input);
                     }
                     component main = PubkeyHasher(121, 17);
                     */
        const inputs = await generateEmailVerifierInputs(rawEmail);
        const publicKey = inputs.pubkey;
        let publicKeyArr = publicKey.map(BigInt);

        const out = await this.pubkeyHasher(121, 17, publicKeyArr);
        return out;
    }

    public static async pubkeyHasher(n: number, k: number, pubkey: bigint[]) {
        let k2_chunked_size = Math.floor(k / 2);
        if (k % 2 === 1) {
            k2_chunked_size += 1;
        }
        let pubkey_hash_input = new Array(k2_chunked_size);
        for (let i = 0; i < k2_chunked_size; i++) {
            if (i === k2_chunked_size - 1 && k2_chunked_size % 2 === 1) {
                pubkey_hash_input[i] = BigInt(pubkey[2 * i]);
            } else {
                pubkey_hash_input[i] =
                    BigInt(pubkey[2 * i]) +
                    (BigInt(1) << BigInt(n)) * BigInt(pubkey[2 * i + 1]);
            }
        }
        const out = poseidon.hash(pubkey_hash_input);
        return out;
    }

    /**
     * generate proof from eml file path or eml content
     *
     * @param {string} emlFilePathOrEmlContent
     * @param {bigint} senderCommitmentRand
     * @return {*}  {(Promise<IEmailProof | null>)}
     * @memberof EmailProof
     */
    public async proveFromEml(
        emlFilePathOrEmlContent: string,
        senderCommitmentRand: bigint
    ): Promise<IEmailProof | null> {
        // check if the input is a file path or the content of the eml file
        let rawEmail: string;
        if (emlFilePathOrEmlContent.endsWith(".eml")) {
            rawEmail = readFileSync(emlFilePathOrEmlContent, "utf8");
        } else {
            rawEmail = emlFilePathOrEmlContent;
        }
        if (!rawEmail.includes("subject:")) {
            throw new Error("The email content is not valid");
        }

        const inputs = await generateEmailVerifierInputs(rawEmail);
        const emailHeader = Buffer.from(inputs.emailHeader.map((c) => Number(c)));
        const subjectPrefixBuffer = Buffer.from("subject:");
        const subjectIndex =
            emailHeader.indexOf(subjectPrefixBuffer) + subjectPrefixBuffer.length;
        const headerSelectorBuffer = Buffer.from("\r\nfrom:");
        const senderEmailNameEmailIndex =
            emailHeader.indexOf(headerSelectorBuffer) + headerSelectorBuffer.length;
        const senderEmailIndex =
            emailHeader
                .subarray(senderEmailNameEmailIndex)
                .indexOf(Buffer.from("<")) +
            senderEmailNameEmailIndex +
            1;
        const senderDomainIndex =
            emailHeader.subarray(senderEmailIndex).indexOf(Buffer.from("@")) + 1;

        const circuitinput: IEmailApproverCircuitInputs = {
            email_header: inputs.emailHeader,
            email_header_length: inputs.emailHeaderLength,
            pubkey: inputs.pubkey,
            signature: inputs.signature,
            sender_email_idx: senderEmailIndex.toString(),
            sender_email_commitment_rand: senderCommitmentRand.toString(),
            sender_domain_idx: senderDomainIndex.toString(),
            subject_idx: subjectIndex.toString(),
        };

        return this.proveFromCircuitinput(circuitinput);
    }

    /**
     * generate proof from circuit input
     *
     * @param {IEmailApproverCircuitInputs} circuitinput
     * @return {*}  {(Promise<IEmailProof | null>)}
     * @memberof EmailProof
     */
    public async proveFromCircuitinput(
        circuitinput: IEmailApproverCircuitInputs
    ): Promise<IEmailProof | null> {
        try {
            const proveData = await this._fullProve(
                circuitinput,
                this._file_wasm,
                this._file_zkey
            );
            if (proveData === null) {
                return null;
            }
            const { proof, publicSignals } = proveData;

            const res = await groth16.verify(this.vKey, publicSignals, proof);
            if (res === true) {
                // get contract inputs
                const _controlAddress = BigInt(publicSignals[3]).toString(16);
                const _approvedHash = (
                    (BigInt(publicSignals[4]) << BigInt(128)) +
                    BigInt(publicSignals[5])
                ).toString(16);
                return {
                    proof: [
                        BigInt(proof.pi_a[0]),
                        BigInt(proof.pi_a[1]),
                        BigInt(proof.pi_b[0][0]),
                        BigInt(proof.pi_b[0][1]),
                        BigInt(proof.pi_b[1][0]),
                        BigInt(proof.pi_b[1][1]),
                        BigInt(proof.pi_c[0]),
                        BigInt(proof.pi_c[1]),
                    ],
                    pubkeyHash: BigInt(publicSignals[0]),
                    senderDomainHash: BigInt(publicSignals[1]),
                    senderCommitment: BigInt(publicSignals[2]),
                    controlAddress:
                        "0x" + "0".repeat(40 - _controlAddress.length) + _controlAddress,
                    approvedHash:
                        "0x" + "0".repeat(64 - _approvedHash.length) + _approvedHash,
                };
            } else {
                console.log("Invalid proof");
                return null;
            }
        } catch (error) {
            console.error(error);
            return null;
        }
    }

    private _randomSeed = 0;
    private _randomString(): string {
        return (
            this._randomSeed++ +
            "" +
            new Date().getTime() +
            "" +
            Math.floor(Math.random() * 100000)
        );
    }

    // DO NOT USE execAsync, it will cause the process to hang
    private _execPromise(command: string): Promise<string> {
        return new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(stdout);
                }
            });
        });
    }

    private async _fullProve(
        circuitinput: IEmailApproverCircuitInputs,
        wasmFile: string,
        zkeyFile: string
    ): Promise<{
        proof: Groth16Proof;
        publicSignals: PublicSignals;
    } | null> {
        // get random string
        const randomString = this._randomString();
        const tmpDir = join(this._tmpDir, randomString);
        if (!existsSync(tmpDir)) {
            mkdirSync(tmpDir);
        }

        // write the circuit input to file
        const circuitInputFile = join(tmpDir, `circuit_input.json`);
        writeFileSync(circuitInputFile, JSON.stringify(circuitinput));

        // generate `witness.wtns`, node generate_witness.js EmailApprover.wasm input.json witness.wtns
        const witnessFile = join(tmpDir, `witness.wtns`);
        await this._execPromise(
            `node ${join(
                this.generateWitnessJsDir,
                "generate_witness.js"
            )} ${wasmFile} ${circuitInputFile} ${witnessFile}`
        );
        if (!existsSync(witnessFile)) {
            console.error("Failed to generate witness file");
            return null;
        }

        try {
            if (this._rapidsnarkProverBin) {
                const proofFile = join(tmpDir, `proof.json`);
                const publicFile = join(tmpDir, `public.json`);
                await this._execPromise(
                    `${this._rapidsnarkProverBin} ${zkeyFile} ${witnessFile} ${proofFile} ${publicFile}`
                );

                if (!existsSync(proofFile) || !existsSync(publicFile)) {
                    console.error("Failed to generate proof");
                    return null;
                }

                let _proof: any = JSON.parse(readFileSync(proofFile).toString("utf-8"));
                let _publicSignals: string[] = JSON.parse(
                    readFileSync(publicFile).toString("utf-8")
                );
                if (!_proof || !_publicSignals) {
                    console.error("Failed to generate proof");
                    return null;
                }
                if (_publicSignals.length !== 6) {
                    console.error("Invalid public signals");
                    return null;
                }

                let proof: Groth16Proof = _proof as Groth16Proof;
                let publicSignals: PublicSignals = _publicSignals as PublicSignals;

                return {
                    proof,
                    publicSignals,
                };
            } else {
                return await groth16.prove(zkeyFile, witnessFile);
            }
        } catch (error) {
            console.error(error);
            return null;
        } finally {
            // remove the tmp directory
            rm(tmpDir, { recursive: true }, () => { });
        }
    }
}
