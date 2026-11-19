package com.example;

import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

public class App {
    public static void main(String[] args) throws Exception {
        // --- 1. 기본 설정 ---
        String privateKey = "0xb8fc6b068e2d6106f925ae8f160ba05ad8fcecab055c0983464bd348a5f08523";
        Credentials credentials = Credentials.create(privateKey);
        BigInteger expectedPublicKey = credentials.getEcKeyPair().getPublicKey();
        String senderAddress = credentials.getAddress();
        String toAddress = "0xbDA5747bFD65F08deb54cb465eB87D40e51B197E";

        System.out.println("Sender Address: " + senderAddress);

        // --- 2. 트랜잭션 내용물(RawTransaction) 생성 ---
        BigInteger nonce = BigInteger.ZERO;
        BigInteger gasPrice = BigInteger.valueOf(20_000_000_000L); // 20 Gwei
        BigInteger gasLimit = BigInteger.valueOf(21_000L);
        BigInteger value = Convert.toWei("1.0", Convert.Unit.ETHER).toBigInteger(); // 1 Ether
        long chainId = 31337; // Hardhat's default chain ID

        RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, toAddress, value, "");

        // --- 3. 서명 대상이 될 올바른 RLP 데이터 생성 (EIP-155) ---
        byte[] encodedTxForHashing = TransactionEncoder.encode(rawTransaction, new Sign.SignatureData(BigInteger.valueOf(chainId).toByteArray(), new byte[]{}, new byte[]{}));
        // 이 값을 Rust에 messageBytes로 전달하면 됩니다.
        System.out.println("RLP Encoded Transaction for Hashing: " + Numeric.toHexString(encodedTxForHashing));
        byte[] transactionHash = org.web3j.crypto.Hash.sha3(encodedTxForHashing);

        // --- 4. Rust 서명 값 및 서명 검증 ---
        String rHex = "b031b09cad37139304b09c954e9888b9a565b9c6e84027f1066fd22c93438328";
        String sHex = "734b34fdceac69330bbda16cddc20625ee2159be9ad26cf90046b948fd900f6a";
        byte[] r = Numeric.hexStringToByteArray(rHex);
        byte[] s = Numeric.hexStringToByteArray(sHex);
        String vHex = "f4f5" ; // 62709 in decimal
        long v = Numeric.toBigInt(vHex).longValue();

        ECDSASignature sig = new ECDSASignature(new BigInteger(1, r), new BigInteger(1, s));
        Integer correctRecId = null;

        for (int i = 0; i < 4; i++) {
            BigInteger recoveredPublicKey = Sign.recoverFromSignature(i, sig, transactionHash);
            if (recoveredPublicKey != null && expectedPublicKey.equals(recoveredPublicKey)) {
                correctRecId = i;
                break;
            }
        }

        if (correctRecId == null) {
            System.out.println("\n--- Signature Verification FAILED. Aborting. ---");
            return;
        }
        System.out.println("\n--- Signature Verification PASSED. Found recId: " + correctRecId + " ---");

        // --- 5. 최종 서명된 트랜잭션 생성 및 전송 ---
        Sign.SignatureData signatureData = new Sign.SignatureData(BigInteger.valueOf(v).toByteArray(), r, s);
        byte[] signedMessage = TransactionEncoder.encode(rawTransaction, signatureData);
        String hexValue = Numeric.toHexString(signedMessage);

        System.out.println("\n--- Connecting to Hardhat to send the transaction ---");
        Web3j web3j = Web3j.build(new HttpService("http://127.0.0.1:8545"));

        EthGetBalance balanceBeforeFrom = web3j.ethGetBalance(senderAddress, DefaultBlockParameterName.LATEST).send();
        EthGetBalance balanceBeforeTo = web3j.ethGetBalance(toAddress, DefaultBlockParameterName.LATEST).send();
        System.out.println("Sender balance before: " + Convert.fromWei(balanceBeforeFrom.getBalance().toString(), Convert.Unit.ETHER) + " ETH");
        System.out.println("Receiver balance before: " + Convert.fromWei(balanceBeforeTo.getBalance().toString(), Convert.Unit.ETHER) + " ETH");

        System.out.println("\nSending transaction...");
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

        if (ethSendTransaction.hasError()) {
            System.out.println("Transaction failed: " + ethSendTransaction.getError().getMessage());
        } else {
            System.out.println("Transaction successful! Hash: " + ethSendTransaction.getTransactionHash());
        }

        EthGetBalance balanceAfterFrom = web3j.ethGetBalance(senderAddress, DefaultBlockParameterName.LATEST).send();
        EthGetBalance balanceAfterTo = web3j.ethGetBalance(toAddress, DefaultBlockParameterName.LATEST).send();
        System.out.println("\nSender balance after: " + Convert.fromWei(balanceAfterFrom.getBalance().toString(), Convert.Unit.ETHER) + " ETH");
        System.out.println("Receiver balance after: " + Convert.fromWei(balanceAfterTo.getBalance().toString(), Convert.Unit.ETHER) + " ETH");

        web3j.shutdown();
    }
}