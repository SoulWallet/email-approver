import { join } from 'path';
import { EmailProof } from "./emailProof";


async function main() {
    // get parent directory on windows and linux
    const _parentDir = join(__dirname, '..');
    const _file_wasm = join(_parentDir, "zkpFiles", 'EmailApprover.wasm');
    const _file_zkey = join(_parentDir, "zkpFiles", 'emailapprover_final.zkey');
    const _file_vkey = join(_parentDir, "zkpFiles", 'verification_key.json');

    //#region EmailAddrCommit test
    {
        /*
            input 1: 12322
            input 2: xurigong@gmail.com
            output: 21770830330223450464430503989801104958781861536559456253001293349309810700942
        */
        const emailAddr = "xurigong@gmail.com";
        const commitment_rand = BigInt(12322);
        const addressCommit = EmailProof.emailAddrCommit(emailAddr, commitment_rand); // static method
        if (addressCommit !== BigInt("21770830330223450464430503989801104958781861536559456253001293349309810700942")) {
            throw new Error("EmailAddrCommit test failed");
        }
    }
    //#endregion

    //#region EmailProof test

    const emailProof = new EmailProof(_file_wasm, _file_zkey, _file_vkey);
    const commitment_rand = BigInt(12322);
    const proof = await emailProof.proveFromEml(join(_parentDir, "emls", "example2.eml"), commitment_rand);
    if (proof === null) {
        throw new Error("EmailProof test failed");
    }
    console.log("EmailProof test passed");

    //#endregion

}

main();