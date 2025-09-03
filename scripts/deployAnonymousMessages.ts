import { ethers } from "hardhat";

/**
 * Simple deployment script for the AnonymousMessages contract.
 *
 * Usage:
 *   MNEMONIC=your mnemonic \
 *   INFURA_API_KEY=your_infura_key \
 *   npx hardhat run scripts/deployAnonymousMessages.ts --network sepolia
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", await deployer.getAddress());

  const factory = await ethers.getContractFactory("AnonymousMessages");
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  console.log("AnonymousMessages deployed to:", await contract.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
