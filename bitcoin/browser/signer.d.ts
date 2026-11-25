export interface PartyFiles {
  envelope: Blob;
  aesKey: Blob;
  identity: Blob;
}
export interface PaymentReview {
  sender_address: string;
  recipient_address: string;
  sent_sat: number;
  fee_sat: number;
  change_sat: number;
  input_sighashes: string[];
}
export interface SignedTransaction {
  txid: string;
  raw_tx_hex: string;
  sent_sat: number;
  change_sat: number;
  fee_sat: number;
  vsize: number;
}
export function reviewPayment(packageJson: string): Promise<PaymentReview>;
export function signWithServer(options: {
  packageJson: string;
  purpose: 'normal_sign' | 'recovery' | 'inheritance';
  ticket: string;
  files: PartyFiles;
  stepsUrl?: string;
  signal?: AbortSignal;
}): Promise<SignedTransaction>;
export function signOffline(options: {
  packageJson: string;
  userFiles: PartyFiles;
  recoveryFiles: PartyFiles;
  signal?: AbortSignal;
}): Promise<SignedTransaction>;
