pragma circom 2.1.6;

include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/circuits/utils/regex.circom";
include "@zk-email/circuits/utils/constants.circom";
include "@zk-email/circuits/utils/bytes.circom";
include "@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/email_domain_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/subject_all_regex.circom";
include "./utils/email_addr_commit.circom";
include "./utils/subject_approval.circom";

/// Verify the email with subject as "Approve address 0x... for hash 0x..."
template EmailApprover(max_header_bytes, max_subject_bytes, n, k) {

    signal input email_header[max_header_bytes];
    signal input email_header_length;
    signal input pubkey[k];                     // dkim public key
    signal input signature[k];                  // dkim signature
    signal input sender_email_idx;              // index of the from email address (= sender email address) in the email header
    signal input sender_email_commitment_rand;  // random value to commit to the sender email address
    signal input sender_domain_idx;             // index of the domain of the sender in the sender email address
    signal input subject_idx;                   // index of the subject in the header
    
    signal output pubkey_hash;                  // hash of the dkim public key
    signal output sender_domain_hash;           // hash of domain of the sender email address
    signal output sender_commitment;            // commitment to the sender email address
    signal output control_address;              // the address to execute the approval
    signal output approval_hash[2];             // the hash to approve

    var email_addr_max_bytes = EMAIL_ADDR_MAX_BYTES();
    var domain_bytes_len = DOMAIN_MAX_BYTES();

    // 1. Verify dkim signature
    component EV = EmailVerifier(max_header_bytes, 0, n, k, 1);
    EV.emailHeader <== email_header;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.emailHeaderLength <== email_header_length;

    pubkey_hash <== EV.pubkeyHash;
    // log("pubkey_hash", pubkey_hash);

    // 2. Verify sender_commitment = commit(sener_email_address, random)
    // extract sender email address

    signal from_regex_out, from_regex_reveal[max_header_bytes];
    (from_regex_out, from_regex_reveal) <== FromAddrRegex(max_header_bytes)(email_header);
    from_regex_out === 1;
    signal sender_email_addr[email_addr_max_bytes];
    sender_email_addr <== SelectRegexReveal(max_header_bytes, email_addr_max_bytes)(from_regex_reveal, sender_email_idx);
    // calculate sender address commitment
    var num_email_addr_ints = computeIntChunkLength(email_addr_max_bytes);
    signal sender_email_addr_ints[num_email_addr_ints] <== PackBytes(email_addr_max_bytes)(sender_email_addr);
    sender_commitment <== EmailAddrCommit(num_email_addr_ints)(sender_email_commitment_rand, sender_email_addr_ints);
    // log("sender_commitment", sender_commitment);

    // 3. Verify email_sender domain
    signal domain_regex_out, domain_regex_reveal[email_addr_max_bytes];
    // note: we must only extract the domain part from the email address, not from all the header
    (domain_regex_out, domain_regex_reveal) <== EmailDomainRegex(email_addr_max_bytes)(sender_email_addr);
    domain_regex_out === 1;
    signal sender_domain_bytes[domain_bytes_len];
    sender_domain_bytes <== SelectRegexReveal(email_addr_max_bytes, domain_bytes_len)(domain_regex_reveal, sender_domain_idx);
    var num_domain_len = computeIntChunkLength(domain_bytes_len);
    signal sender_domain_ints[num_domain_len] <== PackBytes(domain_bytes_len)(sender_domain_bytes);
    sender_domain_hash <== Poseidon(num_domain_len)(sender_domain_ints);
    // log("sender_domain_hash", sender_domain_hash);

    // 4. Verify control address and approval hash
    // extract subject
    signal subject_regex_out, subject_regex_reveal[max_header_bytes];
    (subject_regex_out, subject_regex_reveal) <== SubjectAllRegex(max_header_bytes)(email_header);
    subject_regex_out === 1;
    signal subject_all[max_subject_bytes];
    subject_all <== SelectRegexReveal(max_header_bytes, max_subject_bytes)(subject_regex_reveal, subject_idx);
    (control_address, approval_hash) <== SubjectApproval(max_subject_bytes)(subject_all);
    // log("control_address", control_address);
    // log("approval_hash", approval_hash[0], approval_hash[1]);
}


component main = EmailApprover(1024, 256, 121, 17);