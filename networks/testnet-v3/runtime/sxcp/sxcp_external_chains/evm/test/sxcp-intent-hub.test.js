const { expect } = require("chai");
const { ethers } = require("hardhat");

async function deploySuite() {
  const [admin, relayerA, relayerB, relayerC] = await ethers.getSigners();

  const GovernanceModule = await ethers.getContractFactory("GovernanceModule");
  const governance = await GovernanceModule.deploy(admin.address);
  await governance.waitForDeployment();

  const WitnessRegistry = await ethers.getContractFactory("WitnessRegistry");
  const witnessRegistry = await WitnessRegistry.deploy(admin.address, 2, [
    relayerA.address,
    relayerB.address,
    relayerC.address,
  ]);
  await witnessRegistry.waitForDeployment();

  const SignatureVerifier = await ethers.getContractFactory("SignatureVerifier");
  const signatureVerifier = await SignatureVerifier.deploy(await witnessRegistry.getAddress());
  await signatureVerifier.waitForDeployment();

  const FinalityChecker = await ethers.getContractFactory("FinalityChecker");
  const finalityChecker = await FinalityChecker.deploy(admin.address, [11155111, 80002], [5, 10]);
  await finalityChecker.waitForDeployment();

  const StateProofValidator = await ethers.getContractFactory("StateProofValidator");
  const stateProofValidator = await StateProofValidator.deploy(admin.address, false);
  await stateProofValidator.waitForDeployment();

  const AuditLogger = await ethers.getContractFactory("AuditLogger");
  const auditLogger = await AuditLogger.deploy();
  await auditLogger.waitForDeployment();

  const SXCPIntentHub = await ethers.getContractFactory("SXCPIntentHub");
  const intentHub = await SXCPIntentHub.deploy(
    admin.address,
    await signatureVerifier.getAddress(),
    await finalityChecker.getAddress(),
    await stateProofValidator.getAddress(),
    await auditLogger.getAddress()
  );
  await intentHub.waitForDeployment();

  return {
    admin,
    relayerA,
    relayerB,
    relayerC,
    intentHub,
  };
}

function sortSignerTuples(tuples) {
  return tuples.sort((a, b) => a.signer.address.toLowerCase().localeCompare(b.signer.address.toLowerCase()));
}

describe("SXCPIntentHub", function () {
  it("verifies and consumes an attestation bundle", async function () {
    const { admin, relayerA, relayerB, relayerC, intentHub } = await deploySuite();
    const [_, __, ___, user] = await ethers.getSigners();

    await intentHub.connect(admin).setRemoteEndpoint(11155111, relayerA.address, relayerB.address, true);

    const destinationChainId = 80002;
    const latestBlock = await ethers.provider.getBlock("latest");
    const expiry = Number(latestBlock.timestamp) + 3600;
    const scopeDigest = ethers.keccak256(ethers.toUtf8Bytes("scope:test"));
    const intentId = ethers.keccak256(
      ethers.solidityPacked(["address", "uint256"], [user.address, BigInt(Date.now())])
    );

    await intentHub.connect(user).publishIntent(intentId, destinationChainId, scopeDigest, expiry, 1n);

    const sourceChainId = 11155111;
    const sourceBlockNumber = 100;
    const sourceLogIndex = 0;
    const observedSourceHead = 110;
    const sourceCommitmentRef = ethers.keccak256(ethers.toUtf8Bytes("source-commitment-ref"));
    const stateProofRoot = ethers.keccak256(ethers.toUtf8Bytes("proof-root"));
    const epochId = 1;

    const destinationNetwork = await ethers.provider.getNetwork();
    const digest = await intentHub.computeAttestationDigest(
      sourceChainId,
      Number(destinationNetwork.chainId),
      intentId,
      scopeDigest,
      sourceCommitmentRef,
      sourceBlockNumber,
      sourceLogIndex,
      expiry,
      epochId,
      stateProofRoot
    );

    const signerTuples = sortSignerTuples([
      { signer: relayerA },
      { signer: relayerB },
      { signer: relayerC },
    ]);

    const selected = signerTuples.slice(0, 2);
    const signers = selected.map((item) => item.signer.address);
    const signatures = [];
    for (const item of selected) {
      signatures.push(await item.signer.signMessage(ethers.getBytes(digest)));
    }

    const tx = await intentHub.verifyAttestationBundle(
      sourceChainId,
      intentId,
      scopeDigest,
      sourceCommitmentRef,
      sourceBlockNumber,
      sourceLogIndex,
      observedSourceHead,
      expiry,
      epochId,
      stateProofRoot,
      signers,
      signatures
    );
    const receipt = await tx.wait();
    const eventTopic = intentHub.interface.getEvent("AttestationVerified").topicHash;
    const intentHubAddress = (await intentHub.getAddress()).toLowerCase();
    const eventLog = receipt.logs.find(
      (log) =>
        log.address.toLowerCase() === intentHubAddress &&
        log.topics[0] === eventTopic
    );
    const parsed = intentHub.interface.parseLog(eventLog);
    const attestationId = parsed.args.attestationId;

    expect(await intentHub.isAttestationConsumable(attestationId)).to.equal(true);
    await intentHub.connect(user).consumeVerifiedAttestation(attestationId);
    expect(await intentHub.isAttestationConsumable(attestationId)).to.equal(false);
  });

  it("rejects below-threshold signer bundles", async function () {
    const { admin, relayerA, relayerB, intentHub } = await deploySuite();

    await intentHub.connect(admin).setRemoteEndpoint(11155111, relayerA.address, relayerB.address, true);

    const latestBlock = await ethers.provider.getBlock("latest");
    const expiry = Number(latestBlock.timestamp) + 3600;
    const scopeDigest = ethers.keccak256(ethers.toUtf8Bytes("scope:threshold"));
    const intentId = ethers.keccak256(ethers.toUtf8Bytes("intent:threshold"));
    const sourceCommitmentRef = ethers.keccak256(ethers.toUtf8Bytes("source:threshold"));
    const stateProofRoot = ethers.keccak256(ethers.toUtf8Bytes("proof:threshold"));
    const destinationNetwork = await ethers.provider.getNetwork();

    const digest = await intentHub.computeAttestationDigest(
      11155111,
      Number(destinationNetwork.chainId),
      intentId,
      scopeDigest,
      sourceCommitmentRef,
      200,
      0,
      expiry,
      1,
      stateProofRoot
    );

    const signer = relayerA;
    const signers = [signer.address];
    const signatures = [await signer.signMessage(ethers.getBytes(digest))];

    let reverted = false;
    try {
      await intentHub.verifyAttestationBundle(
        11155111,
        intentId,
        scopeDigest,
        sourceCommitmentRef,
        200,
        0,
        206,
        expiry,
        1,
        stateProofRoot,
        signers,
        signatures
      );
    } catch (error) {
      reverted = true;
      expect(String(error.message)).to.include("reverted");
    }
    expect(reverted).to.equal(true);
  });
});
