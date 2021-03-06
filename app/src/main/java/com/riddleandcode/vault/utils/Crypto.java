package com.riddleandcode.vault.utils;

import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.cms.CMSException;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.operator.OperatorCreationException;

import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.security.cert.X509Certificate;

/**
 * Created by Eyliss on 1/31/17.
 */

public class Crypto {

    public static final String CURVE_NAME = "secp256r1";
    private final String[] ECCurves = new String[] { "","B-233","K-233","B-283", "K-283"};

    /**
     * verify the message depending of the signature and the key.
     *
     * @param message the message
     * @param sign the signature
     * @param key the public key.
     * @return true, if successful
     */
    public static boolean verify(byte[] message, byte[] sign, byte[] key) throws CertificateException, CMSException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());

        try {

            PublicKey testKey = getPublicKeyFromBytes(key);
            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initVerify(testKey);
            signature.update(message);

//            boolean success = signature.verify(message);
//            Log.d("Crypto","Verification success: " + success);

            return false;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static KeyPair generate() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "SC");
        generator.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        return keyPair;
    }

    public static PublicKey getRSAPublicKeyFromString(String apiKey) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SC");
        byte[] publicKeyBytes = Base64.decode(apiKey.getBytes("UTF-8"), Base64.DEFAULT);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(x509KeySpec);
    }

//    private static PublicKey getPublicKeyFromBytes(byte[] pubKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
//        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
//        KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
//        ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
//        java.security.spec.ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKeyBytes);
//        java.security.spec.ECPublicKeySpec pubKeySpec = new java.security.spec.ECPublicKeySpec(point, params);
//        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
//
//        return pk;
//    }

//    private static PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
//
//        byte[] rowbyte = new byte[64];
//
//        for (int i = 0; i <64 ; i++) {
//            if (i<32)
//                rowbyte[i] = (byte) pubKey[31-i];
//            else
//                rowbyte[i] = (byte) pubKey[95-i];
//        }
//        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256r1");//select curve
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
//        kpg.initialize(ecParamSpec);
//        KeyPair kpA = kpg.generateKeyPair();
//        ECPublicKey apk= (ECPublicKey) kpA.getPublic();//get a publickey in secp256r1 format
//        byte[] android_pk_encode = apk.getEncoded();
//        System.arraycopy(rowbyte,0,android_pk_encode,android_pk_encode.length-rowbyte.length,rowbyte.length);
//        //keep the head remained while replace the ECPoint data by the row byte array from 10040
//        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(android_pk_encode);
//        KeyFactory keyFactory = KeyFactory.getInstance("EC");
//        ECPublicKey ECDHpk  = null;
//        try {
//            ECDHpk = (ECPublicKey) keyFactory.generatePublic(ecpks);
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();//failed in generating publickey!!!
//        }
//        return ECDHpk;//show the information by textview in an activity
//
//    }

    private static PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
        java.security.spec.ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKey);
        java.security.spec.ECPublicKeySpec pubKeySpec = new java.security.spec.ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        Log.d("Crypto","Public key "+pk);

        return pk;
    }

    /**
     * This method converts the uncompressed raw EC public key into java.security.interfaces.ECPublicKey
     * @return java.security.interfaces.ECPublicKey
     */
//    public static ECPublicKey getPublicKeyFromBytes(byte[] rawPublicKey) {
//        ECPublicKey ecPublicKey = null;
//        KeyFactory kf = null;
//
//        ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
//        ECCurve curve = ecNamedCurveParameterSpec.getCurve();
//        EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, ecNamedCurveParameterSpec.getSeed());
//        java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve, rawPublicKey);
//        java.security.spec.ECParameterSpec ecParameterSpec = EC5Util.convertSpec(ellipticCurve, ecNamedCurveParameterSpec);
//        java.security.spec.ECPublicKeySpec publicKeySpec = new java.security.spec.ECPublicKeySpec(ecPoint, ecParameterSpec);
//
//        try {
//            kf = KeyFactory.getInstance("EC");
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//
//        try {
//            ecPublicKey = (ECPublicKey) kf.generatePublic(publicKeySpec);
//        } catch (Exception e) {
//            System.out.println("Caught Exception public key: " + e.toString());
//        }
//
//        return ecPublicKey;
//    }

    /**
     * Special class to abstract a Certificate
     */
    public class X509Certif  {

        private static final String EXCEPTION_ERROR_VERIFY_CERTIFICATE = "Error to verify the certificate";
        private static final String EXCEPTION_ERROR_EXTRACT_PUBKEY_DPMISMATCH = "Error mismatch between public key in certificate and device's domain parameter";
        private static final String EXCEPTION_ERROR_EXTRACT_PUBKEY = "Error extracting public key";


        public final X509Certificate theCertif;

        public X509Certif(X509Certificate certif) {
            theCertif = certif;
        }

        /**
         * Verify a given certificate with the supposed signing certificate
         *
         * @param certificate the supposed signing certificate of the field  theCertif
         *
         * @throws CryptoException in case of problem during verification
         */
        public void certificateVerify(X509Certif certificate) throws CryptoException
        {
            try {
                // Verify the given certificate with the given public key
                theCertif.verify(certificate.theCertif.getPublicKey());
            } catch (javax.security.cert.CertificateException e) {
                throw new CryptoException(EXCEPTION_ERROR_VERIFY_CERTIFICATE);
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException(EXCEPTION_ERROR_VERIFY_CERTIFICATE);
            } catch (InvalidKeyException e) {
                throw new CryptoException(EXCEPTION_ERROR_VERIFY_CERTIFICATE);
            } catch (NoSuchProviderException e) {
                throw new CryptoException(EXCEPTION_ERROR_VERIFY_CERTIFICATE);
            } catch (SignatureException e) {
                throw new CryptoException(EXCEPTION_ERROR_VERIFY_CERTIFICATE);
            }
        }

        /**
         * Provide the public key found in the certificate.
         * If desired, compared the ECC Domain parameter found in the extracted key
         * and the one provided (which should be the one found in VaultIC's GetInfo)
         *
         * @param compareDPParam True if we want the method to compare the domain parameter
         * @param expDpID The ECC domain parameter find directly in VaultIC15x, it should match
         *                the parameters found in the Public Key in the Certificate
         * @return The public key as a String
         */
        public String extractPubKeyFromCertificate(boolean compareDPParam,String expDpID) throws CryptoException {
            ECParameterSpec ecspec;

            // Extract public key from certificate
            PublicKey devPK = theCertif.getPublicKey();

            ECPublicKey ecDevPK = (ECPublicKey)devPK;
            // Get parameters
            ecspec = ecDevPK.getParameters();

            if (compareDPParam) {

                byte[] paramID = new byte[1];
                paramID = Util.parseByteArray(expDpID, 2);

                // Expected ECC Domain Parameter
                ECParameterSpec expectedEcSpec = ECNamedCurveTable.getParameterSpec(SECNamedCurves.getName(ECCNamedCurves.getOID(ECCurves[paramID[0]])));

                /////
                // Check that EC Domain Parameters attached to public key extracted from certificate
                // are matching the one given
                if (expectedEcSpec.equals(ecspec) == false) {
                    throw new CryptoException(EXCEPTION_ERROR_EXTRACT_PUBKEY_DPMISMATCH);
                }
            }

            // Needed for padding
            int orderLength = ecspec.getN().bitLength();
            while ( (orderLength%32) != 0 ) orderLength++;
            orderLength = orderLength/8;

            // Extract coordinate of public key, and reconstruct public key in relevant format
            // for VaultIC15x (with padding)
            org.spongycastle.math.ec.ECPoint point = ecDevPK.getQ();
            String Xstr = point.getAffineXCoord().toString();
            String Ystr = point.getAffineYCoord().toString();
            // Apply padding
            int lenZero = orderLength*2 - Xstr.length();
            if (lenZero<0) throw new CryptoException(EXCEPTION_ERROR_EXTRACT_PUBKEY);
            for (int ind=0;ind<lenZero;ind++) {
                Xstr = "0" + Xstr;
            }
            lenZero = orderLength*2 - Ystr.length();
            if (lenZero<0) throw new CryptoException(EXCEPTION_ERROR_EXTRACT_PUBKEY);
            for (int ind=0;ind<lenZero;ind++) {
                Ystr = "0" + Ystr;
            }
            return (Xstr+Ystr);
        }
    }
}
