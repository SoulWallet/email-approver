
import { DKIMKey } from './DKIMKey';
import fs from 'fs';

const DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "aol.com",
    "protonmail.com",
    "proton.me"
];

const DKIM_ARCHIVE_FILE = "DKIM_archive.md";

async function main() {

    const rows: string[] = [];

    for (let i = 0; i < DOMAINS.length; i++) {
        const domain = DOMAINS[i];
        console.log(`Getting DKIM keys for domain ${domain}`);
        const keys = await DKIMKey.listDKIMKeys(domain);
        console.log(`Got ${keys.length} DKIM keys for domain ${domain}`);
        if (keys.length > 0) {
            for (let j = 0; j < keys.length; j++) {
                const key = keys[j];
                rows.push(`| ${key.domain} | ${key.domainHash} | ${key.selector} | ${key.firstSeenAt} | ${key.lastSeenAt} | ${key.publicKeyHash} | ${key.value} |`);
            }
        } else {
            rows.push(`| ${domain} | | | | | | |`);
        }
        // sleep for 2 second to avoid rate limit
        await new Promise(resolve => setTimeout(resolve, 2000));
    }

    const tableHeader = `| domain    | domain hash | selector | firstSeenAt | lastSeenAt | public key hash | value |
| --------- | ----------- | -------- | ----------- | ---------- | --------------- | ----- |`;

    fs.writeFileSync(DKIM_ARCHIVE_FILE,
        `# DKIM Key Archive\n\n` +
        tableHeader + "\n" + rows.join("\n") + "\n" +
        "\n```shell\nnpm run exportDKIMPubKey\n```\n\n\n\n\nPowered by archive.prove.email"
    );



}

main();