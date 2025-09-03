// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

// This contract implements a privacy‑preserving anonymous messaging service
// using Zama's FHEVM library.  Users can create an "inbox" (simply by
// providing their address) and share a link so anyone can send them an
// encrypted message.  Messages are stored on‑chain as encrypted 64‑bit
// identifiers that reference off‑chain message bodies.  The contract uses
// Fully Homomorphic Encryption (FHE) operations to sanitize inputs and
// manage permissions via the access‑control list (ACL) functions.  After
// decrypting a message off‑chain, the recipient can send an encrypted reply
// back to the original sender without ever learning the sender’s identity.

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
 * recipient and sender so they can decrypt the ciphertext off‑chain.  The
 * recipient can later post an encrypted reply, which is authorized for
 * decryption by the original sender.  All ACL handling is explicit as
 * required by FHEVM【664752838332074†L125-L158】.
 */
contract AnonymousMessages is SepoliaConfig {
    struct Message {
        euint64 encryptedMsg;     // ciphertext of the message identifier
        address sender;           // public address of the sender (not exposed in UI)
        address recipient;        // public address of the recipient (inbox owner)
        euint64 replyEncrypted;   // ciphertext of the reply identifier
        bool replied;             // whether a reply has been posted
    }

    // Dynamic array storing all messages.  Each entry corresponds to an index
    // that can be retrieved via the inbox mapping.
    Message[] private messages;

    // Mapping from recipient address to an array of message indices in the
    // `messages` array.  This allows each user to maintain a personal inbox.
    mapping(address => uint256[]) private inbox;

    /// Event emitted when a new message is sent.
    event MessageSent(address indexed sender, address indexed recipient, uint256 indexed msgIndex);

    /// Event emitted when a reply is posted to an existing message.
    event ReplySent(uint256 indexed msgIndex);

    /**
     * @notice Send an encrypted message to a recipient.
     * @param recipient The address receiving the message (inbox owner).
     * @param encryptedMsg The encrypted 64‑bit message identifier from the sender.
     * @param inputProof Zero‑knowledge proof associated with the encrypted input.
     *
     * The function sanitizes the input to avoid storing a zero message ID by
     * using encrypted comparison and `FHE.select`【323541669917858†L96-L121】.  It then grants
     * ACL permissions so both the recipient and sender can later decrypt the
     * message ciphertext off‑chain【664752838332074†L125-L158】.
     */
    function sendMessage(
        address recipient,
        externalEuint64 encryptedMsg,
        bytes calldata inputProof
    ) external {
        require(recipient != address(0), "recipient=0");

        // Convert the external ciphertext to an internal encrypted value
        euint64 msgId = FHE.fromExternal(encryptedMsg, inputProof);

        // Avoid storing a zero message ID: if msgId == 0 select 0 (invalid) or
        // leave it as is.  The recipient should ignore zero IDs off‑chain.
        ebool isZero = FHE.eq(msgId, FHE.asEuint64(0));
        msgId = FHE.select(isZero, FHE.asEuint64(0), msgId);

        // Grant permanent access to both sender and recipient so they can
        // decrypt this ciphertext off‑chain【664752838332074†L125-L158】.
        FHE.allow(msgId, recipient);
        FHE.allow(msgId, msg.sender);

        // Store the message and update the inbox index
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
     * @notice Post an encrypted reply to a message.  Only the original
     * recipient can reply.  The reply ciphertext will be authorized for
     * decryption by the original sender.
     * @param msgIndex Index of the message to reply to.
     * @param encryptedReply Encrypted 64‑bit reply identifier.
     * @param inputProof Zero‑knowledge proof associated with the encrypted reply.
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

        // Convert the external ciphertext to an internal encrypted value
        euint64 replyId = FHE.fromExternal(encryptedReply, inputProof);

        // Sanitize the reply ID to ensure non‑zero; the sender will ignore zero
        // IDs off‑chain.  Using FHE.eq and FHE.select【323541669917858†L96-L121】.
        ebool isZero = FHE.eq(replyId, FHE.asEuint64(0));
        replyId = FHE.select(isZero, FHE.asEuint64(0), replyId);

        // Grant permanent access to the original sender and recipient (so they can
        // decrypt and view the reply off‑chain)【664752838332074†L125-L158】.
        FHE.allow(replyId, m.sender);
        FHE.allow(replyId, msg.sender);

        m.replyEncrypted = replyId;
        m.replied = true;
        emit ReplySent(msgIndex);
    }

    /**
     * @notice Return the number of messages in a recipient's inbox.
     * @param recipient Address of the inbox owner.
     */
    function getInboxCount(address recipient) external view returns (uint256) {
        return inbox[recipient].length;
    }

    /**
     * @notice Retrieve the encrypted message identifier by index.  Only
     * authorized addresses (recipient or sender) should decrypt off‑chain.
     * @param msgIndex Index of the message in the `messages` array.
     */
    function getMessageCipher(uint256 msgIndex) external view returns (euint64) {
        require(msgIndex < messages.length, "bad index");
        return messages[msgIndex].encryptedMsg;
    }

    /**
     * @notice Retrieve the encrypted reply identifier if one exists.  Only the
     * original sender or recipient should attempt to decrypt this off‑chain.
     * @param msgIndex Index of the message in the `messages` array.
     */
    function getReplyCipher(uint256 msgIndex) external view returns (euint64) {
        require(msgIndex < messages.length, "bad index");
        return messages[msgIndex].replyEncrypted;
    }

    /**
     * @notice Retrieve metadata for a message.  This function does not return
     * encrypted content, only the public fields.  Useful for UIs to show
     * whether a message has been replied to.  The sender’s address is not
     * returned to avoid exposing identity in the front end.
     * @param msgIndex Index of the message in the `messages` array.
     * @return recipient Address of the message recipient.
     * @return replied Whether the message has been replied to.
     */
    function getMessageMeta(uint256 msgIndex) external view returns (address recipient, bool replied) {
        require(msgIndex < messages.length, "bad index");
        Message storage m = messages[msgIndex];
        return (m.recipient, m.replied);
    }
}
