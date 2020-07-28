import { Block, Transaction, address, networks, payments, script, } from 'bitcoinjs-lib';
import { ElectrumWS, bytesToHex, } from '../electrum-ws/index';
export class ElectrumApi {
    constructor(options = {}) {
        if (typeof options.network === 'string') {
            options.network = networks[options.network];
        }
        this.options = options;
        const eWSOptions = {};
        if ('proxy' in this.options)
            eWSOptions.proxy = this.options.proxy;
        if ('token' in this.options)
            eWSOptions.token = this.options.token;
        this.socket = new ElectrumWS(this.options.endpoint, eWSOptions);
    }
    async getBalance(address) {
        return this.socket.request('blockchain.scripthash.get_balance', await this.addressToScriptHash(address));
    }
    async getReceipts(address, isScriptHash = false) {
        const receipts = await this.socket.request('blockchain.scripthash.get_history', isScriptHash ? script : await this.addressToScriptHash(address));
        return receipts.map((r) => ({
            blockHeight: r.height,
            transactionHash: r.tx_hash,
            ...(r.fee ? { fee: r.fee } : {}),
        }));
    }
    async getHistory(address) {
        const history = await this.getReceipts(address);
        history.sort((a, b) => (b.blockHeight || Number.MAX_SAFE_INTEGER) - (a.blockHeight || Number.MAX_SAFE_INTEGER));
        const blockHeights = history.reduce((array, entry) => {
            const height = entry.blockHeight;
            if (height > 0)
                array.push(height);
            return array;
        }, []);
        const blockHeaders = new Map();
        for (const height of blockHeights) {
            try {
                blockHeaders.set(height, await this.getBlockHeader(height));
            }
            catch (error) {
                console.error(error);
                break;
            }
        }
        const txs = [];
        for (const { transactionHash, blockHeight } of history) {
            try {
                const tx = await this.getTransaction(transactionHash);
                const blockHeader = blockHeaders.get(blockHeight);
                if (blockHeader) {
                    tx.blockHeight = blockHeight;
                    tx.timestamp = blockHeader.timestamp;
                    tx.blockHash = blockHeader.blockHash;
                }
                txs.push(tx);
            }
            catch (error) {
                console.error(error);
                return txs;
            }
        }
        return txs;
    }
    async getTransaction(hash, height) {
        const raw = await this.socket.request('blockchain.transaction.get', hash);
        let blockHeader;
        if (typeof height === 'number' && height > 0) {
            try {
                blockHeader = await this.getBlockHeader(height);
            }
            catch (error) {
                console.error(error);
            }
        }
        return this.transactionToPlain(raw, blockHeader);
    }
    async getBlockHeader(height) {
        const raw = await this.socket.request('blockchain.block.header', height);
        return this.blockHeaderToPlain(raw, height);
    }
    async broadcastTransaction(rawTx) {
        const tx = this.transactionToPlain(rawTx);
        const hash = await this.socket.request('blockchain.transaction.broadcast', rawTx);
        if (hash === tx.transactionHash)
            return tx;
        else
            throw new Error(hash);
    }
    async subscribeReceipts(address, callback) {
        this.socket.subscribe('blockchain.scripthash', async (scriptHash, status) => {
            callback(await this.getReceipts(scriptHash, true));
        }, await this.addressToScriptHash(address));
    }
    async subscribeHeaders(callback) {
        this.socket.subscribe('blockchain.headers', async (headerInfo) => {
            callback(this.blockHeaderToPlain(headerInfo.hex, headerInfo.height));
        });
    }
    transactionToPlain(tx, plainHeader) {
        if (typeof tx === 'string')
            tx = Transaction.fromHex(tx);
        const plain = {
            transactionHash: tx.getId(),
            inputs: tx.ins.map((input, index) => this.inputToPlain(input, index)),
            outputs: tx.outs.map((output, index) => this.outputToPlain(output, index)),
            version: tx.version,
            vsize: tx.virtualSize(),
            isCoinbase: tx.isCoinbase(),
            weight: tx.weight(),
            blockHash: null,
            blockHeight: null,
            timestamp: null,
        };
        if (plainHeader) {
            plain.blockHash = plainHeader.blockHash;
            plain.blockHeight = plainHeader.blockHeight;
            plain.timestamp = plainHeader.timestamp;
        }
        return plain;
    }
    inputToPlain(input, index) {
        return {
            script: input.script,
            transactionHash: bytesToHex(input.hash.reverse()),
            address: this.deriveAddressFromInput(input) || null,
            witness: input.witness,
            index,
            outputIndex: input.index,
        };
    }
    outputToPlain(output, index) {
        return {
            script: output.script,
            address: address.fromOutputScript(output.script, this.options.network),
            value: output.value,
            index,
        };
    }
    deriveAddressFromInput(input) {
        const chunks = (script.decompile(input.script) || []);
        const witness = input.witness;
        if (chunks.length === 2 && witness.length === 0) {
            return payments.p2pkh({
                pubkey: chunks[1],
                network: this.options.network,
            }).address;
        }
        if (chunks.length === 1 && witness.length === 2) {
            return payments.p2sh({
                redeem: payments.p2wpkh({
                    pubkey: witness[1],
                    network: this.options.network,
                }),
            }).address;
        }
        if (chunks.length === 0 && witness.length === 2) {
            return payments.p2wpkh({
                pubkey: witness[1],
                network: this.options.network,
            }).address;
        }
        if (chunks.length > 2 && witness.length === 0) {
            const m = chunks.length - 2;
            const pubkeys = script.decompile(chunks[chunks.length - 1])
                .filter((n) => typeof n !== 'number');
            return payments.p2sh({
                redeem: payments.p2ms({
                    m,
                    pubkeys,
                    network: this.options.network,
                }),
            }).address;
        }
        if (chunks.length === 1 && witness.length > 2) {
            const m = witness.length - 2;
            const pubkeys = script.decompile(witness[witness.length - 1])
                .filter((n) => typeof n !== 'number');
            return payments.p2sh({
                redeem: payments.p2wsh({
                    redeem: payments.p2ms({
                        m,
                        pubkeys,
                        network: this.options.network,
                    }),
                }),
            }).address;
        }
        if (chunks.length === 0 && witness.length > 2) {
            const m = witness.length - 2;
            const pubkeys = script.decompile(witness[witness.length - 1])
                .filter((n) => typeof n !== 'number');
            return payments.p2wsh({
                redeem: payments.p2ms({
                    m,
                    pubkeys,
                    network: this.options.network,
                }),
            }).address;
        }
        console.error(new Error('Cannot decode address from input'));
        return undefined;
    }
    blockHeaderToPlain(header, height) {
        if (typeof header === 'string')
            header = Block.fromHex(header);
        return {
            blockHash: header.getId(),
            blockHeight: height,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            version: header.version,
            weight: header.weight(),
            prevHash: header.prevHash ? bytesToHex(header.prevHash.reverse()) : null,
            merkleRoot: header.merkleRoot ? bytesToHex(header.merkleRoot) : null,
        };
    }
    async addressToScriptHash(addr) {
        const outputScript = address.toOutputScript(addr, this.options.network);
        const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', outputScript));
        return bytesToHex(hash.reverse());
    }
}
