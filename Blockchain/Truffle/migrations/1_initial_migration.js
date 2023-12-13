const Migrations = artifacts.require("Migrations");
const FederatedModel = artifacts.require("FederatedModel")
const verifier = artifacts.require("Verifier")
const Registration = artifacts.require("Registration")
const RegistrationVerifier = artifacts.require("RegistrationVerifier")
const fs = require('fs');
const yaml = require('js-yaml');

module.exports = function (deployer) {
 let fileContents = fs.readFileSync('/home/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations/CONFIG.yaml', 'utf8');
  let data = yaml.load(fileContents);
  deployer.deploy(Migrations);
  deployer.deploy(FederatedModel,data.DEFAULT.InputDimension,data.DEFAULT.OutputDimension,data.DEFAULT.LearningRate,data.DEFAULT.Precision,data.DEFAULT.BatchSize,data.DEFAULT.IntervalTime);
  deployer.deploy(verifier,{gas:data.DEFAULT.Gas});
  deployer.deploy(Registration);
  deployer.deploy(RegistrationVerifier,{gas:data.DEFAULT.Gas});
};


