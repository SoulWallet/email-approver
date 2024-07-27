# Contribution Guide


[The ZK Setup Ceremony ended on UTC 2024-07-27](trusted-setup-ceremony/README.md)

Welcome to the SoulWallet - zkEmail Approver Phase 2 Trusted Setup Ceremony. This ZK circuit will be used for the zkEmail social recovery feature of the smart contract wallet.

1. **Install [Node](https://nodejs.org/en/download/) (> v16)**

2. **Install `@soulwallet/phase2cli-zkemailapprover`**

   Run the following command:

   ```shell
   npm install -g @soulwallet/phase2cli-zkemailapprover
   ```

3. **Log in with your GitHub account**

   Run:

   ```shell
   phase2cli-zkemailapprover auth
   ```

   GitHub account requirements:

   ```ini
   Followers >= 1
   Following >= 2
   Public Repos >= 2
   Account age >= 1 month
   ```

4. **Contribute**

   Run:

   ```shell
   phase2cli-zkemailapprover contribute -c emailapprover
   ```

   During the process, you will need to download 1.2GB of files and upload 1.2GB of files. Additionally, you will need approximately 10-40 minutes of CPU computation time (depending on your computer). All of the above must be completed within 60 minutes for the contribution to be valid.

5. **Done!**

You have successfully contributed.
