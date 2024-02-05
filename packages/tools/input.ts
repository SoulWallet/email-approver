import { generateCircuitInputs } from "@zk-email/helpers/dist/input-helpers";
import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim"
import fs from "fs"
import path from "path"
 
export const MAX_HEADER_PADDED_BYTES = 1024;
export const MAX_BODY_PADDED_BYTES = 1024;
 
export async function generateTwitterVerifierCircuitInputs() {
    const rawEmail = fs.readFileSync(
        path.join(__dirname, "./emls/example2.eml"),
        "utf8"
      );
    const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
    const emailVerifierInputs = generateCircuitInputs({
        rsaSignature: dkimResult.signature,
        rsaPublicKey: dkimResult.publicKey,
        body: dkimResult.body,
        bodyHash:dkimResult.bodyHash,
        message: dkimResult.message,
        // shaPrecomputeSelector: STRING_PRESELECTOR,
        maxMessageLength: MAX_HEADER_PADDED_BYTES,
        maxBodyLength: MAX_BODY_PADDED_BYTES
    });
 
    const inHeader = Buffer.from(emailVerifierInputs.in_padded!.map(c => Number(c)));
    console.log("in_padded:\n", emailVerifierInputs.in_padded!.map(c => String.fromCharCode(parseInt(c))).join(""))

    const subjectPrefixBuffer = Buffer.from("subject:");
    const subjectIndex = inHeader.indexOf(subjectPrefixBuffer) + subjectPrefixBuffer.length;

    const headerSelectorBuffer = Buffer.from("\r\nfrom:");
    const senderEmailNameEmailIndex = inHeader.indexOf(headerSelectorBuffer) + headerSelectorBuffer.length;
    const senderEmailIndex = inHeader.slice(senderEmailNameEmailIndex).indexOf(Buffer.from("<")) + senderEmailNameEmailIndex + 1;
    console.log("senderEmailNameEmailIndex", senderEmailNameEmailIndex, "senderEmailIndex", senderEmailIndex);

    const senderDomainIndex = inHeader.slice(senderEmailIndex).indexOf(Buffer.from("@")) + 1;
    console.log("senderDomainIndex", senderDomainIndex);

    const senderCommitmentRand = "12322";

    emailVerifierInputs.body_hash_idx = undefined;
    emailVerifierInputs.precomputed_sha = undefined;
    emailVerifierInputs.in_body_padded = undefined;
    emailVerifierInputs.in_body_len_padded_bytes = undefined;
    const inputJson = {
        ...emailVerifierInputs,
        sender_email_idx: senderEmailIndex.toString(),
        sender_email_commitment_rand: senderCommitmentRand,
        sender_domain_idx: senderDomainIndex.toString(),
        subject_idx: subjectIndex.toString()
    };
    fs.writeFileSync("./input.json", JSON.stringify(inputJson, undefined, 4))
}
 
(async () => {
    await generateTwitterVerifierCircuitInputs();
}) ();
 