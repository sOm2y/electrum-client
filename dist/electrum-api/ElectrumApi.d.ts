import { Block, Network, Transaction, TxInput, TxOutput } from 'bitcoinjs-lib';
import { Balance, PlainBlockHeader, PlainInput, PlainOutput, PlainTransaction, Receipt } from './types';
export declare type Options = {
    endpoint?: string;
    network?: Network;
    proxy?: boolean;
    token?: string;
};
export declare class ElectrumApi {
    private options;
    private socket;
    constructor(options?: Omit<Options, 'network'> & {
        network?: 'bitcoin' | 'testnet' | 'regtest' | Network;
    });
    getBalance(address: string): Promise<Balance>;
    getReceipts(address: string, isScriptHash?: boolean): Promise<Receipt[]>;
    getHistory(address: string): Promise<PlainTransaction[]>;
    getTransaction(hash: string, height?: number): Promise<PlainTransaction>;
    getBlockHeader(height: number): Promise<PlainBlockHeader>;
    broadcastTransaction(rawTx: string): Promise<PlainTransaction>;
    subscribeReceipts(address: string, callback: (receipts: Receipt[]) => any): Promise<void>;
    subscribeHeaders(callback: (header: PlainBlockHeader) => any): Promise<void>;
    transactionToPlain(tx: string | Transaction, plainHeader?: PlainBlockHeader): PlainTransaction;
    inputToPlain(input: TxInput, index: number): PlainInput;
    outputToPlain(output: TxOutput, index: number): PlainOutput;
    deriveAddressFromInput(input: TxInput): string | undefined;
    blockHeaderToPlain(header: string | Block, height: number): PlainBlockHeader;
    private addressToScriptHash;
}
