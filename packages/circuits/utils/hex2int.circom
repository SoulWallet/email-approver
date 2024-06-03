pragma circom 2.1.6;

// `in` is a big-endtian hex string of `out`.
template Hex2Field(n) {
    signal input in[n];
    signal output out;
    var num_bytes = n / 2;
    signal bytes[num_bytes] <== Hex2Ints(n)(in);
    signal sums[num_bytes + 1];
    sums[0] <== 0;
    for(var i = 0; i < num_bytes; i++) {
        sums[i+1] <== 256 * sums[i] + bytes[i];
    }
    out <== sums[num_bytes];
}

template Hex2Ints(n) {
    assert(n % 2 == 0);
    var bytes = n / 2;
    signal input in[n];
    signal output out[bytes];

    component hex2int[n];
    for(var i = 0; i < bytes; i++) {
        for(var j = 0; j < 2; j++) {
            hex2int[2*i+j] = Hex2Int1();
            hex2int[2*i+j].in <== in[2*i+j];
        }
        out[i] <== 16 * hex2int[2*i].out + hex2int[2*i+1].out;  
    }
}

template Hex2Int1() {
    signal input in;
    signal output out;

    // the given char is [0-9].
    signal is_digit_min_in[2];
    is_digit_min_in[0] <== in;
    is_digit_min_in[1] <== 48;
    signal is_digit_min <== GreaterEqThan(8)(is_digit_min_in);
    signal is_digit_max_in[2];
    is_digit_max_in[0] <== in;
    is_digit_max_in[1] <== 57;
    signal is_digit_max <== LessEqThan(8)(is_digit_max_in);
    signal is_digit <== is_digit_min * is_digit_max;
    
    // the given char is [a-f].
    signal is_alphabet_min_in[2];
    is_alphabet_min_in[0] <== in;
    is_alphabet_min_in[1] <== 97;
    signal is_alphabet_min <== GreaterEqThan(8)(is_alphabet_min_in);
    signal is_alphabet_max_in[2];
    is_alphabet_max_in[0] <== in;
    is_alphabet_max_in[1] <== 102;
    signal is_alphabet_max <== LessEqThan(8)(is_alphabet_max_in);
    signal is_alphabet <== is_alphabet_min * is_alphabet_max;

    is_digit + is_alphabet === 1;  
    signal digit_int <== is_digit * (in - 48);
    // 87 = 97 - 10
    signal alphabet_int <== is_alphabet * (in - 87);
    out <== digit_int + alphabet_int;
}