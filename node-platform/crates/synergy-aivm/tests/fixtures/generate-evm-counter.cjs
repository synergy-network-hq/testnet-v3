// Reproduce this fixture using solc0.8.30 and ethers6.15.0, supplied as explicit
// module paths. The private scalar is the PUBLIC EIP155 example test key.
const fs = require('node:fs');
const path = require('node:path');
const solc = require(process.argv[2]);
const ethers = require(process.argv[3]);
if (!solc.version().startsWith('0.8.30+') || ethers.version !== '6.15.0') throw Error('Fixture compiler/client version differs');
(async () => {
  const source = fs.readFileSync(path.join(__dirname, 'EvmCounter.sol'), 'utf8');
  const settings = {evmVersion: 'shanghai', optimizer: {enabled: true, runs: 200},
    outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object']}}};
  const compiled = JSON.parse(solc.compile(JSON.stringify({language: 'Solidity', sources: {'EvmCounter.sol': {content: source}}, settings})));
  if (compiled.errors?.some(error => error.severity === 'error')) throw Error(JSON.stringify(compiled.errors));
  const contract = compiled.contracts['EvmCounter.sol'].EvmCounter;
  const wallet = new ethers.Wallet('0x' + '46'.repeat(32));
  const address = ethers.getCreateAddress({from: wallet.address, nonce: 0});
  const iface = new ethers.Interface(contract.abi);
  const recipient = '0x' + '35'.repeat(20);
  const inputs = [
    {nonce: 0, data: '0x' + contract.evm.bytecode.object},
    {nonce: 1, to: address, data: iface.encodeFunctionData('set', [42])},
    {nonce: 2, to: address, data: iface.encodeFunctionData('fail')},
    {nonce: 3, to: address, data: iface.encodeFunctionData('value')},
    {nonce: 4, to: address, value: 1000000000n, data: iface.encodeFunctionData('pay', [recipient, 1])},
    {nonce: 4, to: address, value: 1000000000n, data: iface.encodeFunctionData('pay', [recipient, 1000000000])},
    {nonce: 4, to: address, value: 1000000000n, data: iface.encodeFunctionData('pay', [recipient, 0])},
    {nonce: 5, to: address, data: iface.encodeFunctionData('destroy', [recipient])},
    {nonce: 5, to: address, data: iface.encodeFunctionData('destroy', [address])},
    {nonce: 0, to: recipient, value: 1000000000000000000n, data: '0x'},
  ];
  const transactions = [];
  for (const input of inputs) {
    const raw = await wallet.signTransaction({type: 0, chainId: 9969, gasPrice: 20000000000n, gasLimit: 1000000, ...input});
    transactions.push({raw, hash: ethers.keccak256(raw)});
  }
  fs.writeFileSync(path.join(__dirname, 'evm-counter-shanghai.json'), JSON.stringify({compiler: solc.version(), ethers: ethers.version,
    sourceKeccak: ethers.keccak256(ethers.toUtf8Bytes(source)), settings, sender: wallet.address, address,
    abi: contract.abi, bytecode: contract.evm.bytecode.object, runtime: contract.evm.deployedBytecode.object, transactions}, null, 2) + '\n');
  console.log('Generated actual Solidity/ethers Shanghai fixture: ' + address);
})().catch(error => { console.error(error); process.exitCode = 1; });
