
pragma circom 2.1.6;

include "./hex2int.circom";

// Ensure that the subject is like "Approve address 0x{40 bytes} for hash 0x{64 bytes}"
template SubjectApproval(max_subject_bytes) {
    signal input subject[max_subject_bytes];

    signal output control_address;
    signal output approval_hash[2];

    // extract control_address
    signal control_address_hex[40];
    control_address_hex <== VarShiftLeft(max_subject_bytes, 40)(subject, 18);
    control_address <== Hex2Field(40)(control_address_hex);

    // extract approval_hash
    signal approval_hash_hex[64];
    component HF1 = Hex2Field(32);
    component HF2 = Hex2Field(32);
    signal hex1[32], hex2[32];
    approval_hash_hex <== VarShiftLeft(max_subject_bytes, 64)(subject, 70);
    for (var i = 0; i < 32; i++) {
        hex1[i] <== approval_hash_hex[i];
        hex2[i] <== approval_hash_hex[i+32];
    }
    HF1.in <== hex1;
    HF2.in <== hex2;
    approval_hash[0] <== HF1.out;
    approval_hash[1] <== HF2.out;

    subject[0] === 65; // A
    subject[1] === 112; // p
    subject[2] === 112; // p
    subject[3] === 114; // r
    subject[4] === 111; // o
    subject[5] === 118; // v
    subject[6] === 101; // e
    subject[7] === 32; // ' '
    subject[8] === 97; // a
    subject[9] === 100; // d
    subject[10] === 100; // d
    subject[11] === 114; // r
    subject[12] === 101; // e
    subject[13] === 115; // s
    subject[14] === 115; // s
    subject[15] === 32; // ' '

    subject[16] === 48; // 0
    subject[17] === 120; // x

    // 18 - 57: 40 bytes

    subject[58] === 32; // ' '
    subject[59] === 102; // f
    subject[60] === 111; // o
    subject[61] === 114; // r
    subject[62] === 32; // ' '
    subject[63] === 104; // h
    subject[64] === 97; // a
    subject[65] === 115; // s
    subject[66] === 104; // s
    subject[67] === 32; // ' '

    subject[68] === 48; // 0
    subject[69] === 120; // x

    // 70 - 133: 64 bytes
}