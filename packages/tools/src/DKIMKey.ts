
import axios from 'axios';
import * as forge from 'node-forge';
import { toCircomBigIntBytes, packBytesIntoNBytes } from "@zk-email/helpers";
import { poseidon } from "@iden3/js-crypto";
import { EmailProof } from "./emailProof";

// https://archive.prove.email/api-explorer
export interface DKIMRecord {
    domain: string
    selector: string
    firstSeenAt: string
    lastSeenAt: string
    value: string
}

export interface GooglePublicDNSResponse {
    Status: number // 0:NOERROR, 3:NXDOMAIN
    TC: boolean
    RD: boolean
    RA: boolean
    AD: boolean
    CD: boolean
    Question: Question[]
    Answer: Answer[]
    Comment: string
}

export interface Question {
    name: string
    type: number // 5:CNAME
}

export interface Answer {
    name: string
    type: number // 5:CNAME, 16:TXT
    TTL: number
    data: string
}
export class DKIMKey {

    private static async fetchGooglePublicDNS(domain: string, type: 'CNAME' | 'TXT'): Promise<Answer[] | null> {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;
        // get json response
        const response = await axios.get(url);
        if (response.status !== 200) {
            throw new Error(`Failed to fetch DNS record for domain ${domain}`);
        }

        const ret = response.data as GooglePublicDNSResponse;
        if (ret.Status === 3 /* NXDOMAIN */) {
            return null;
        }
        if (ret.Status !== 0) {
            throw new Error(`Failed to fetch DNS record for domain ${domain}`);
        }
        if (ret.Answer.length === 0) {
            return null;
        }
        return ret.Answer;

    }
    private static async getDKIMPublicKey(domain: string, selector: string): Promise<string> {
        // check if the domain has a CNAME record
        const host = `${selector}._domainkey.${domain}`;
        const key = await this._getDKIMPublicKey(host);
        return key;
    }

    private static async _getDKIMPublicKey(hostname: string): Promise<string> {
        const records = await this.fetchGooglePublicDNS(hostname, 'TXT');
        if (records === null || records.length === 0) {
            return '';
        }
        for (let index = 0; index < records.length; index++) {
            const record = records[index];
            if (record.type === 16 /* TXT */) {
                return record.data;
            }
        }
        return '';
    }



    private static async pubkeyHasher(n: number, k: number, pubkey: bigint[]) {
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

    public static async listDKIMKeys(domain: string) {
        /*
            curl -X 'GET' \
          'https://archive.prove.email/api/key?domain=google.com' \
          -H 'accept: application/json'
        */
        const response = await axios.get('https://archive.prove.email/api/key', {
            params: {
                domain
            }
        });
        const data = response.data as DKIMRecord[];
        const list = [];
        for (let i = 0; i < data.length; i++) {
            const record = data[i];
            if (record.domain !== domain) {
                continue;
            }
            if (record.value.length < 300) {
                continue;
            }
            /*
                 k=rsa; p=
                 v=DKIM1; k=rsa; p=
                 v=DKIM1;k=rsa;p=
            */
            if (
                !record.value.includes("p=") ||
                !record.value.includes("k=rsa;")
            ) {
                continue;
            }
            const publicKey = await this.getDKIMPublicKey(record.domain, record.selector);
            if (publicKey.length < 300) {
                console.log(`Invalid DKIM public key for selector ${record.selector} and domain ${record.domain}`);
                continue;
            }
            if (publicKey !== record.value) {
                console.log(`Public key in the database: ${record.value}`);
                console.log(`Public key from DNS: ${publicKey}`);
                throw new Error(`DKIM public key for selector ${record.selector} and domain ${record.domain} is different from archive.prove.email and DNS`);
            }
            const pubKeyStr = 'p=';
            let pubKeyBase64: string = publicKey.substring(publicKey.indexOf(pubKeyStr) + pubKeyStr.length);
            const _breakIndex = pubKeyBase64.indexOf(';');
            if (_breakIndex >= 0) {
                pubKeyBase64 = pubKeyBase64.substring(0, _breakIndex);
            }
            const pubKeyBase64Arr = pubKeyBase64.match(/.{1,64}/g);
            if (pubKeyBase64Arr === null) {
                throw new Error('Invalid input');
            }
            const PEMStr = `-----BEGIN PUBLIC KEY-----\n${pubKeyBase64Arr.join('\n')}\n-----END PUBLIC KEY-----`;
            const pubKeyData = forge.pki.publicKeyFromPem(PEMStr);
            const pubKeyBigInt = BigInt(pubKeyData.n.toString());
            const pubKeyCircomInput = toCircomBigIntBytes(pubKeyBigInt);
            const publicKeyArr = pubKeyCircomInput.map(BigInt);
            const _publicKeyHash = BigInt(await this.pubkeyHasher(121, 17, publicKeyArr)).toString(16);
            const publicKeyHash = '0x' + _publicKeyHash.padStart(64, '0');
            const _domainHash = EmailProof.emailDomainHash(record.domain).toString(16);
            const domainHash = '0x' + _domainHash.padStart(64, '0');

            list.push({
                domain: record.domain,
                domainHash: domainHash,
                selector: record.selector,
                firstSeenAt: record.firstSeenAt,
                lastSeenAt: record.lastSeenAt,
                value: publicKey,
                publicKeyHash: publicKeyHash,
            });
        }
        // order by firstSeenAt desc
        list.sort((a, b) => {
            return new Date(b.firstSeenAt).getTime() - new Date(a.firstSeenAt).getTime();
        });
        return list;

    }
} 