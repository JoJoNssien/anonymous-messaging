// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {FHE, externalEuint64, euint64, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {SepoliaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/**
 * @title AnonymousMessages
 * @notice Privacy‑preserving message board with encrypted messages and replies.
 *
 * Each message consists of an encrypted 64‑bit identifier pointing to the
 * message body stored off‑chain.  The sender’s address is recorded but
 * never revealed to the recipient by default.  When a message is sent,
 * the contract grants permanent access (via `FHE.allow`) to both the
 * recipient and sender so they can decrypt the ciphertext off‑chain:contentReference[oaicite:0]{index=0}.
 * The recipient can later post an encrypted reply, which is authorized for
 * decryption by the original sender.  All ACL handling is explicit as
 * required by FHEVM:contentReference[oaicite:1]{index=1}.
 */
contract AnonymousMessages is SepoliaConfig {
    struct Message {
        euint64 encryptedMsg;     // ciphertext of the message identifier
        address sender;           // address of the sender (public)
        address recipient;        // address of the recipient (public)
        euint64 replyEncrypted;   // ciphertext of the reply identifier
        bool replied;             // whether a reply has been posted
    }

    Message[] private messages;
    mapping(address => uint256[]) private inbox;

    event MessageSent(address indexed sender, address indexed recipient, uint256 indexed msgIndex);
    event ReplySent(uint256 indexed msgIndex);

    /**
     * @notice Send an encrypted message to a recipient.
     * @param recipient The address receiving the message.
     * @param encryptedMsg The encrypted 64‑bit message identifier.
     * @param inputProof Zero‑knowledge proof associated with the encrypted input.
     */
    function sendMessage(
        address recipient,
        externalEuint64 encryptedMsg,
        bytes calldata inputProof
    ) external {
        require(recipient != address(0), "recipient=0");

        // Convert external ciphertext to internal encrypted value
        euint64 msgId = FHE.fromExternal(encryptedMsg, inputProof);

        // If ID == 0 (invalid), store 0; recipient should ignore zero IDs.
        ebool isZero = FHE.eq(msgId, FHE.asEuint64(0));
        msgId = FHE.select(isZero, FHE.asEuint64(0), msgId);

        // Grant permanent access to both sender and recipient
        FHE.allow(msgId, recipient);
        FHE.allow(msgId, msg.sender);
        // Also allow the contract itself (for testing and on‑chain decryption)
        FHE.allowThis(msgId);

        uint256 index = messages.length;
        messages.push(Message({
            encryptedMsg: msgId,
            sender: msg.sender,
            recipient: recipient,
            replyEncrypted: FHE.asEuint64(0),
            replied: false
        }));
        inbox[recipient].push(index);

        emit MessageSent(msg.sender, recipient, index);
    }

    /**
     * @notice Post an encrypted reply to a message. Only the original
     * recipient can reply.  The reply ciphertext will be authorized for
     * decryption by the original sender.
     * @param msgIndex Index of the message to reply to.
     * @param encryptedReply Encrypted 64‑bit reply identifier.
     * @param inputProof Zero‑knowledge proof for the encrypted reply.
     */
    function sendReply(
        uint256 msgIndex,
        externalEuint64 encryptedReply,
        bytes calldata inputProof
    ) external {
        require(msgIndex < messages.length, "bad index");
        Message storage m = messages[msgIndex];
        require(!m.replied, "already replied");
        require(msg.sender == m.recipient, "not message recipient");

        euint64 replyId = FHE.fromExternal(encryptedReply, inputProof);

        // Sanitize reply ID to avoid zero
        ebool isZero = FHE.eq(replyId, FHE.asEuint64(0));
        replyId = FHE.select(isZero, FHE.asEuint64(0), replyId);

        // Grant access to original sender and recipient
        FHE.allow(replyId, m.sender);
        FHE.allow(replyId, msg.sender);
        // Allow the contract itself to decrypt the reply
        FHE.allowThis(replyId);

        m.replyEncrypted = replyId;
        m.replied = true;
        emit ReplySent(msgIndex);
    }

    function getInboxCount(address recipient) external view returns (uint256) {
        return inbox[recipient].length;
    }

    function getInboxMessageIndex(address recipient, uint256 pos) external view returns (uint256) {
        require(pos < inbox[recipient].length, "pos out of bounds");
        return inbox[recipient][pos];
    }

    function getMessageCipher(uint256 msgIndex) external view returns (euint64) {
        require(msgIndex < messages.length, "bad index");
        return messages[msgIndex].encryptedMsg;
    }

    function getReplyCipher(uint256 msgIndex) external view returns (euint64) {
        require(msgIndex < messages.length, "bad index");
        return messages[msgIndex].replyEncrypted;
    }

    function getMessageMeta(uint256 msgIndex) external view returns (address recipient, bool replied) {
        require(msgIndex < messages.length, "bad index");
        Message storage m = messages[msgIndex];
        return (m.recipient, m.replied);
    }
}
chore: update AnonymousMessages.sol (FHE.allowThis + reply ACL)
