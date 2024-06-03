import { readFileSync, existsSync } from 'fs';
import { generateEmailVerifierInputs } from "@zk-email/helpers";
import { groth16 } from 'snarkjs';
import { packBytesIntoNBytes } from "@zk-email/helpers";
import { poseidon } from "@iden3/js-crypto";

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
    proof: bigint[],
    pubkeyHash: bigint,
    senderDomainHash: bigint,
    senderCommitment: bigint,
    controlAddress: string,
    approvedHash: string
}

export class EmailProof {
    private _file_wasm: string;
    private _file_zkey: string;
    private vKey;

    /**
     * Creates an instance of EmailProof.
     * @param {string} file_wasm the path to the file EmailApprover.wasm
     * @param {string} file_zkey the path to the file emailapprover_final.zkey
     * @param {string} file_vkey the path to the file verification_key.json
     * @memberof EmailProof
     */
    constructor(
        file_wasm: string,
        file_zkey: string,
        file_vkey: string
    ) {
        this.vKey = JSON.parse(readFileSync(file_vkey).toString('utf-8'));
        // check if file_wasm and file_zkey exist
        if (!file_wasm || !file_zkey) {
            throw new Error("The file_wasm and file_zkey are required");
        }
        if (!file_wasm.endsWith('.wasm') || !file_zkey.endsWith('.zkey')) {
            throw new Error("The file_wasm must be a .wasm file and the file_zkey must be a .zkey file");
        }
        if (!existsSync(file_wasm) || !existsSync(file_zkey)) {
            throw new Error("The file_wasm and file_zkey must exist");
        }

        this._file_wasm = file_wasm;
        this._file_zkey = file_zkey
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
    public static emailAddrCommit(emailAddr: string, sender_email_commitment_rand: bigint): bigint {
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
        const _sender_email_addr_ints = packBytesIntoNBytes(emailAddr, MAX_BYTES_IN_FIELD);
        const sender_email_addr_ints: bigint[] = [];
        for (
            let index = 0;
            index < (Math.ceil(EMAIL_ADDR_MAX_BYTES / MAX_BYTES_IN_FIELD) /*computeIntChunkLength()*/);
            index++
        ) {
            if (index < _sender_email_addr_ints.length) {
                sender_email_addr_ints[index] = BigInt(_sender_email_addr_ints[index]);
            } else {
                sender_email_addr_ints[index] = BigInt(0);
            }
        }
        const poseidonInputs = [sender_email_commitment_rand, ...sender_email_addr_ints];
        const out = poseidon.hash(poseidonInputs);
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
    public async proveFromEml(emlFilePathOrEmlContent: string, senderCommitmentRand: bigint): Promise<IEmailProof | null> {
        // check if the input is a file path or the content of the eml file
        let rawEmail: string;
        if (emlFilePathOrEmlContent.endsWith('.eml')) {
            rawEmail = readFileSync(emlFilePathOrEmlContent, 'utf8');
        } else {
            rawEmail = emlFilePathOrEmlContent;
        }
        if (!rawEmail.includes("subject:")) {
            throw new Error("The email content is not valid");
        }

        const inputs = await generateEmailVerifierInputs(rawEmail);
        const emailHeader = Buffer.from(inputs.emailHeader.map(c => Number(c)));
        const subjectPrefixBuffer = Buffer.from("subject:");
        const subjectIndex = emailHeader.indexOf(subjectPrefixBuffer) + subjectPrefixBuffer.length;
        const headerSelectorBuffer = Buffer.from("\r\nfrom:");
        const senderEmailNameEmailIndex = emailHeader.indexOf(headerSelectorBuffer) + headerSelectorBuffer.length;
        const senderEmailIndex = emailHeader.subarray(senderEmailNameEmailIndex).indexOf(Buffer.from("<")) + senderEmailNameEmailIndex + 1;
        const senderDomainIndex = emailHeader.subarray(senderEmailIndex).indexOf(Buffer.from("@")) + 1;

        const circuitinput: IEmailApproverCircuitInputs = {
            email_header: inputs.emailHeader,
            email_header_length: inputs.emailHeaderLength,
            pubkey: inputs.pubkey,
            signature: inputs.signature,
            sender_email_idx: senderEmailIndex.toString(),
            sender_email_commitment_rand: senderCommitmentRand.toString(),
            sender_domain_idx: senderDomainIndex.toString(),
            subject_idx: subjectIndex.toString()
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
    public async proveFromCircuitinput(circuitinput: IEmailApproverCircuitInputs): Promise<IEmailProof | null> {
        try {
            const { proof, publicSignals } = await groth16.fullProve(
                circuitinput as any,
                this._file_wasm,
                this._file_zkey
            );

            const res = await groth16.verify(this.vKey, publicSignals, proof);
            if (res === true) {
                // get contract inputs
                const _controlAddress = BigInt(publicSignals[3]).toString(16);
                const _approvedHash = ((BigInt(publicSignals[4]) << BigInt(128)) + BigInt(publicSignals[5])).toString(16);
                return {
                    proof: [
                        BigInt(proof.pi_a[0]),
                        BigInt(proof.pi_a[1]),
                        BigInt(proof.pi_b[0][0]),
                        BigInt(proof.pi_b[0][1]),
                        BigInt(proof.pi_b[1][0]),
                        BigInt(proof.pi_b[1][1]),
                        BigInt(proof.pi_c[0]),
                        BigInt(proof.pi_c[1])
                    ],
                    pubkeyHash: BigInt(publicSignals[0]),
                    senderDomainHash: BigInt(publicSignals[1]),
                    senderCommitment: BigInt(publicSignals[2]),
                    controlAddress: '0x' + '0'.repeat(40 - _controlAddress.length) + _controlAddress,
                    approvedHash: '0x' + '0'.repeat(64 - _approvedHash.length) + _approvedHash
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
}