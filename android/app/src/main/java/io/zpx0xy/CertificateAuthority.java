package io.zpx0xy;

import android.content.Context;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/** Creates an on-device root CA and host certificates for the local proxy. */
final class CertificateAuthority {
    private static final String ALGORITHM = "SHA256withRSA";
    // Android ships its own provider named "BC", which can shadow the bundled full
    // Bouncy Castle implementation and lacks some algorithms used by the signer.
    private final BouncyCastleProvider cryptoProvider = new BouncyCastleProvider();
    private final File directory;
    private final ConcurrentHashMap<String, SSLContext> contexts = new ConcurrentHashMap<>();
    private KeyPair rootPair;
    private X509Certificate rootCertificate;

    CertificateAuthority(Context context) throws Exception {
        directory = new File(context.getFilesDir(), "authority");
        if (!directory.exists() && !directory.mkdirs()) throw new IllegalStateException("Cannot create private CA storage");
        loadOrCreate();
    }

    private void loadOrCreate() throws Exception {
        File certFile = new File(directory, "root.der");
        File keyFile = new File(directory, "root.pk8");
        if (certFile.exists() && keyFile.exists()) {
            try (FileInputStream in = new FileInputStream(certFile)) {
                rootCertificate = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in);
            }
            byte[] key = readFile(keyFile);
            rootPair = new KeyPair(rootCertificate.getPublicKey(), KeyFactory.getInstance("RSA", cryptoProvider).generatePrivate(new PKCS8EncodedKeySpec(key)));
            return;
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", cryptoProvider);
        generator.initialize(3072); rootPair = generator.generateKeyPair();
        Date start = new Date(System.currentTimeMillis() - 60_000L);
        Date end = new Date(System.currentTimeMillis() + 3_650L * 24 * 60 * 60 * 1000);
        X500Name name = new X500Name("CN=ZPX0XY Android Inspection CA");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial(), start, end, name, rootPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        rootCertificate = convert(builder.build(signer(rootPair.getPrivate())));
        try (FileOutputStream out = new FileOutputStream(certFile)) { out.write(rootCertificate.getEncoded()); }
        try (FileOutputStream out = new FileOutputStream(keyFile)) { out.write(rootPair.getPrivate().getEncoded()); }
    }

    SSLContext contextFor(String host) throws Exception {
        String cacheKey = host.toLowerCase(Locale.ROOT);
        SSLContext cached = contexts.get(cacheKey);
        if (cached != null) return cached;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", cryptoProvider); generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        Date start = new Date(System.currentTimeMillis() - 60_000L);
        Date end = new Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000);
        X500Name issuer = new X500Name(rootCertificate.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + host.replaceAll("[^A-Za-z0-9.*-]", "_"));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial(), start, end, subject, pair.getPublic());
        GeneralName san = isIp(host)
            ? new GeneralName(GeneralName.iPAddress, new DEROctetString(InetAddress.getByName(host).getAddress()))
            : new GeneralName(GeneralName.dNSName, host);
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        X509Certificate leaf = convert(builder.build(signer(rootPair.getPrivate())));
        KeyStore store = KeyStore.getInstance("PKCS12"); store.load(null, null);
        store.setKeyEntry("zpx0xy", pair.getPrivate(), new char[0], new java.security.cert.Certificate[]{leaf, rootCertificate});
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); factory.init(store, new char[0]);
        SSLContext context = SSLContext.getInstance("TLS"); context.init(factory.getKeyManagers(), null, null);
        SSLContext prior = contexts.putIfAbsent(cacheKey, context);
        return prior == null ? context : prior;
    }

    byte[] certificate() throws Exception { return rootCertificate.getEncoded(); }

    private ContentSigner signer(PrivateKey key) throws Exception { return new JcaContentSignerBuilder(ALGORITHM).setProvider(cryptoProvider).build(key); }
    private X509Certificate convert(X509CertificateHolder holder) throws Exception { return new JcaX509CertificateConverter().setProvider(cryptoProvider).getCertificate(holder); }
    private BigInteger serial() { return new BigInteger(159, new java.security.SecureRandom()).add(BigInteger.ONE); }
    private boolean isIp(String host) { return host.matches("[0-9.]+") || host.contains(":"); }
    private byte[] readFile(File file) throws Exception {
        try (FileInputStream in = new FileInputStream(file); java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int count; while ((count=in.read(buffer))!=-1) out.write(buffer,0,count); return out.toByteArray();
        }
    }
}
