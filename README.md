# End-to-End Verifiable Decentralized Federated Learning

## Pre-requisites 
- install & run rabbitmq
- Install & run truffle (./start.sh)
- Install &run ganache (optional; can use other test network)
- Execute web server for CA (flask run)

## Initial configuration
- zokrates environment setup
<ul> zokrates file compile (zokrates compile -i root.zok —debug)</ul>
<ul> zokrates proving key generation (zokrates setup) </ul>
<ul> zokrates verifier export (zokrates export-verifier) </ul>

- Contracts deployment (truffle migrate)
<ul> modify all paths in ./Blockchain/Truffle/migration/1_initial_migration.js </ul>
<ul> truffle migrate </ul>

- CONFIG.yaml modification
<ul> Change contract address withn CONFIG.yaml (FLContractAddress, VerifierContractAddress, etc.,) after contract deployment </ul>

## Execution
- python3 main.py
