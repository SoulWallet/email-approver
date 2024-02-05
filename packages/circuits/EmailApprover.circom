pragma circom 2.1.5;
include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/circuits/helpers/extract.circom";
include "./utils/hex2int.circom";
include "./utils/bytes2ints.circom";
include "./utils/constants.circom";
include "./utils/email_addr_commit.circom";
include "./utils/subject_approval.circom";
include "@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/email_domain_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/subject_all_regex.circom";

/// Verify the email with subject as "Approve address 0x... for hash 0x..."
template EmailApprover(max_header_bytes, max_subject_bytes, n, k, pack_size) {
    signal input in_padded[max_header_bytes]; // padded email header
    signal input in_len_padded_bytes; // length of the sha256 padded email header
    signal input pubkey[k]; // dkim public key
    signal input signature[k]; // dkim signature
    // signal input body_hash_idx;
    // signal input precomputed_sha[32];
    // signal input in_body_padded[max_body_bytes];
    // signal input in_body_len_padded_bytes;
    signal input sender_email_idx; // index of the from email address (= sender email address) in the email header
    signal input sender_email_commitment_rand; // random value to commit to the sender email address
    signal input sender_domain_idx; // index of the domain of the sender in the sender email address
    signal input subject_idx; // index of the subject in the header

    var email_addr_max_bytes = email_max_bytes_const();
    var domain_bytes_len = domain_len_const();
    var domain_ints_len = compute_ints_size(domain_bytes_len);
    
    signal output pubkey_hash; // hash of the dkim public key
    signal output sender_domain_hash; // hash of domain of the sender email address
    signal output sender_commitment; // commitment to the sender email address
    signal output control_address; // the address to execute the approval
    signal output approval_hash[2]; // the hash to approve

    // 1. Verify dkim signature
    component EV = EmailVerifier(max_header_bytes, 0, n, k, 1); // ignore body hash check
    EV.in_padded <== in_padded;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.in_len_padded_bytes <== in_len_padded_bytes;
    // EV.body_hash_idx <== body_hash_idx;
    // EV.precomputed_sha <== precomputed_sha;
    // EV.in_body_padded <== in_body_padded;
    // EV.in_body_len_padded_bytes <== in_body_len_padded_bytes;
    pubkey_hash <== EV.pubkey_hash;

    // 2. Verify sender_commitment = commit(sener_email_address, random)
    // extract sender email address
    signal from_regex_out, from_regex_reveal[max_header_bytes];
    (from_regex_out, from_regex_reveal) <== FromAddrRegex(max_header_bytes)(in_padded);
    from_regex_out === 1;
    signal sender_email_addr[email_addr_max_bytes];
    sender_email_addr <== VarShiftMaskedStr(max_header_bytes, email_addr_max_bytes)(from_regex_reveal, sender_email_idx);
    // calculate sender address commitment
    var num_email_addr_ints = compute_ints_size(email_addr_max_bytes);
    signal sender_email_addr_ints[num_email_addr_ints] <== Bytes2Ints(email_addr_max_bytes)(sender_email_addr);
    sender_commitment <== EmailAddrCommit(num_email_addr_ints)(sender_email_commitment_rand, sender_email_addr_ints);

    // 3. Verify email_sender domain
    signal domain_regex_out, domain_regex_reveal[email_addr_max_bytes];
    // note: we must only extract the domain part from the email address, not from all the header
    (domain_regex_out, domain_regex_reveal) <== EmailDomainRegex(email_addr_max_bytes)(sender_email_addr);
    domain_regex_out === 1;
    signal sender_domain_bytes[domain_bytes_len];
    sender_domain_bytes <== VarShiftMaskedStr(email_addr_max_bytes, domain_bytes_len)(domain_regex_reveal, sender_domain_idx);
    signal sender_domain_ints[domain_ints_len] <== Bytes2Ints(domain_bytes_len)(sender_domain_bytes);
    sender_domain_hash <== Poseidon(domain_ints_len)(sender_domain_ints);

    // 4. Verify control address and approval hash
    // extract subject
    signal subject_regex_out, subject_regex_reveal[max_header_bytes];
    (subject_regex_out, subject_regex_reveal) <== SubjectAllRegex(max_header_bytes)(in_padded);
    subject_regex_out === 1;
    signal subject_all[max_subject_bytes];
    subject_all <== VarShiftMaskedStr(max_header_bytes, max_subject_bytes)(subject_regex_reveal, subject_idx);

    (control_address, approval_hash) <== SubjectApproval(max_subject_bytes)(subject_all);

    // TODO: restrict timestamp?

    log("pubkey_hash", pubkey_hash);
    log("sender_commitment", sender_commitment);
    log("control_address", control_address);
    log("approval_hash", approval_hash[0], approval_hash[1]);
    log("sender_domain_bytes");
    for (var i = 0; i < domain_bytes_len; i++) {
        if (sender_domain_bytes[i] != 0) {
            log(sender_domain_bytes[i]);
        }
    }
    log("sender_domain_hash", sender_domain_hash);
}

component main = EmailApprover(1024, 256, 121, 17, 8);