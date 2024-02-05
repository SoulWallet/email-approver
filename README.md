## Email Approver

EIP1271 style approver by verifying user's email on-chain. Powered by [zkemail](https://github.com/zkemail). This can be used as:

1. Email Guardian for smart contract wallet
2. Gnosis-Safe wallet owner


Take Email Guardian as an example. This basicly works as:

1. User input his `email_address`. The relayer generate a random number `email_commitment_rand` and keep it private. Then compute `email_commitment = hash(email_address, email_commitment_rand)`. This is to hide the email address.
2. Deploy the `EmailApprover.sol` with `email_commitment` as init parameter. Set this deplyed contract as guardian.
3. During social recovery. User sends an email to the relayer with subject `Approve address 0x{guardian wallet address} for hash 0x{social recovery hash}`.
4. The relayer generate a proof from email.
5. The relayer trigger `approver` function of the Email Guaridan. The contract will verify the email's DKIM signature and extract the approved hash.
6. If the verify passes, the Email Guardian will approve the given hash. User can then continue to execute Social Recovery.