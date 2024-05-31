import { generateEmailVerifierInputs, generateEmailVerifierInputsFromDKIMResult } from "@zk-email/helpers";
// import { verifyDKIMSignature, DKIMVerificationResult } from "@zk-email/helpers/dist/dkim";

import fs from "fs";
import path from "path";

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

async function main() {
    const rawEmail = fs.readFileSync(
        path.join(__dirname, "../emls/example2.eml"),
        "utf8"
    );
    //  const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
    const inputs = await generateEmailVerifierInputs(rawEmail);
    const emailHeader = Buffer.from(inputs.emailHeader.map(c => Number(c)));
    const subjectPrefixBuffer = Buffer.from("subject:");
    const subjectIndex = emailHeader.indexOf(subjectPrefixBuffer) + subjectPrefixBuffer.length;
    const headerSelectorBuffer = Buffer.from("\r\nfrom:");
    const senderEmailNameEmailIndex = emailHeader.indexOf(headerSelectorBuffer) + headerSelectorBuffer.length;
    const senderEmailIndex = emailHeader.subarray(senderEmailNameEmailIndex).indexOf(Buffer.from("<")) + senderEmailNameEmailIndex + 1;
    const senderDomainIndex = emailHeader.subarray(senderEmailIndex).indexOf(Buffer.from("@")) + 1;
    const senderCommitmentRand = "12322";

    const circuitinput: IEmailApproverCircuitInputs = {
        email_header: inputs.emailHeader,
        email_header_length: inputs.emailHeaderLength,
        pubkey: inputs.pubkey,
        signature: inputs.signature,
        sender_email_idx: senderEmailIndex.toString(),
        sender_email_commitment_rand: senderCommitmentRand,
        sender_domain_idx: senderDomainIndex.toString(),
        subject_idx: subjectIndex.toString()
    };
    fs.writeFileSync("../input.json", JSON.stringify(circuitinput, undefined, 4))
}

main();