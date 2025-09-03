import { expect } from "chai";
import { ethers } from "hardhat";
import { HardhatFhevmRuntimeEnvironment, FhevmType } from "@fhevm/hardhat-plugin";
import { AnonymousMessages, AnonymousMessages__factory } from "../types";

describe("AnonymousMessages", function () {
  let contract: AnonymousMessages;
  let alice: any, bob: any;
  let fhe: HardhatFhevmRuntimeEnvironment;

  before(async () => {
    [alice, bob] = await ethers.getSigners();
    fhe = (hre as any).fhevm;
  });

  beforeEach(async () => {
    const factory = (await ethers.getContractFactory("AnonymousMessages")) as AnonymousMessages__factory;
    contract = (await factory.deploy()) as AnonymousMessages;
    await contract.waitForDeployment();
  });

  it("allows anonymous messaging and replies", async function () {
    const addr = await contract.getAddress();

    // Bob sends a message to Alice.  Off‑chain we represent the message body
    // with numeric ID 7 (for example).  Bob encrypts this under the contract
    // address and his own address.
    const input = await fhe.createEncryptedInput(addr, bob.address);
    input.add64(7);
    const encMsg = await input.encrypt();

    // Send message
    await contract.connect(bob).sendMessage(alice.address, encMsg.handles[0], encMsg.inputProof);

    // Alice checks her inbox and decrypts the message
    const msgCipher = await contract.getMessageCipher(0);
    const clearMsg = await fhe.userDecryptEuint(FhevmType.euint64, msgCipher, addr, alice);
    expect(clearMsg).to.equal(7);

    // Alice sends a reply (e.g., numeric ID 42)
    const replyInput = await fhe.createEncryptedInput(addr, alice.address);
    replyInput.add64(42);
    const encReply = await replyInput.encrypt();

    await contract.connect(alice).sendReply(0, encReply.handles[0], encReply.inputProof);

    // Bob decrypts the reply
    const replyCipher = await contract.getReplyCipher(0);
    const clearReply = await fhe.userDecryptEuint(FhevmType.euint64, replyCipher, addr, bob);
    expect(clearReply).to.equal(42);
  });
});
