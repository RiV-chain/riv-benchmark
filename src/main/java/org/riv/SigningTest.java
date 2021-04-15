
package org.riv;

import java.security.SecureRandom;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes48;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.bls.BLSTestUtil;
import tech.pegasys.teku.bls.impl.blst.BlstLoader;
import tech.pegasys.teku.bls.impl.mikuli.MikuliBLS12381;


public class SigningTest {
	
	static {
		 //BLS.setBlsImplementation(MikuliBLS12381.INSTANCE);
		 BLS.setBlsImplementation(BlstLoader.INSTANCE.get());
	}
	
	 public static void main(String[] args) throws Throwable {
		args = new String[] {"testSignatureAggregate"};
	    if(args==null || args.length==0) {
	    		System.out.println("Test arguments: SignatureVerify, SignatureAggregate, SignatureAggregateVerify\n");
	    		return;
	    	}
	    	String test = args[0];
			System.out.println("Test:"+test);
			if(test.equals("SignatureVerify")) {
				testSignatureVerify();
			} else 
			if(test.equals("testSignatureAggregate")) {
				testSignatureAggregate();
			} else 
			if(test.equals("testSignatureAggregateVerify")) {
				testSignatureAggregateVerify();
			}
		}

		private static String toString(long bytes, long elapseNS) {
			double elapseS = elapseNS / (1000000.0 * 1000.0);
			double bytesM = bytes / (1024.0 * 1024.0);
			double mbs = bytesM / elapseS;
			return NumberFormat.getNumberInstance(Locale.ROOT).format(mbs) + " MB/s";
		}
		
		public static void testSignatureVerify() {
			int payloadSize = 350; // Transaction size
			
			long randomSeed = 13636363L; //the input data seed

			Thread.currentThread().setPriority(Thread.MAX_PRIORITY); //reduce random spikes

			byte[] in = new byte[payloadSize];

			SecureRandom gen = new SecureRandom();

			long totalBytes = 0L,
				 totalElapse = 0L;
			while (true) {
				gen.setSeed(randomSeed);
				gen.nextBytes(in);

				long bytes = in.length;
				
			    Bytes m = Bytes.wrap(in);
			    BLSKeyPair keyPair = BLSTestUtil.randomKeyPair(1);
			    
				BLSSignature sign = BLS.sign(keyPair.getSecretKey(), m);
				byte[] out = sign.toBytesCompressed().toArray();
				
				byte[] pk = keyPair.getPublicKey().toBytesCompressed().toArray();
				byte[] s = sign.toBytesCompressed().toArray();
				long begin = System.nanoTime();
				
				BLS.verify(BLSPublicKey.fromBytesCompressedValidate(Bytes48.wrap(pk)), Bytes.wrap(in), BLSSignature.fromBytesCompressed(Bytes.wrap(s)));

				long end = System.nanoTime();
				long elapse = end - begin;

				totalBytes += bytes;
				totalElapse += elapse;

				System.out.println(payloadSize + " (rand=" + gen.getAlgorithm() + "[seed=" + randomSeed + "]" + ")" + "  \t  " + "cur: " + toString(bytes, elapse) + "  \t  " + "avg: " + toString(totalBytes, totalElapse));
			}
		}
		
		 public static void testSignatureAggregate() throws Throwable {
		    	
				int payloadSize = 350; // Transaction size
				
				long randomSeed = 13636363L; //the input data seed

				Thread.currentThread().setPriority(Thread.MAX_PRIORITY); //reduce random spikes

				byte[] in = new byte[payloadSize];

				SecureRandom gen = new SecureRandom();

				long totalBytes = 0L,
					 totalElapse = 0L;
				int n = 1000;
				while (true) {
					gen.setSeed(randomSeed);
					
					long bytes = in.length*n;
					
					List<Bytes> messages = new ArrayList<Bytes>();
					List<BLSPublicKey> pubKeys = new ArrayList<BLSPublicKey>();
					List<BLSSignature> s = new ArrayList<BLSSignature>();
					
					for(int i=0;i<n;i++) {
						gen.nextBytes(in);
					    Bytes m = Bytes.wrap(in);
					    messages.add(m);
					    BLSKeyPair keyPair = BLSTestUtil.randomKeyPair(1);
						BLSSignature sign = BLS.sign(keyPair.getSecretKey(), m);
						s.add(sign);
						pubKeys.add(keyPair.getPublicKey());
					}
					
					//BLSSignature aggregatedSign = BLS.aggregate(s);
					
					long begin = System.nanoTime();
					
					//BLS.aggregateVerify(pubKeys, messages, aggregatedSign);
					BLSSignature aggregatedSign = BLS.aggregate(s);
					byte[] out = aggregatedSign.toBytesCompressed().toArray();
					long end = System.nanoTime();
					long elapse = end - begin;

					totalBytes += bytes;
					totalElapse += elapse;

					System.out.println(payloadSize + " (rand=" + gen.getAlgorithm() + "[seed=" + randomSeed + "]" + ")" + "  \t  " + "cur: " + toString(bytes, elapse) + "  \t  " + "avg: " + toString(totalBytes, totalElapse));
				}
			}
		
		 public static void testSignatureAggregateVerify() throws Throwable {
		    	
				int payloadSize = 350; // Transaction size
				long randomSeed = 13636363L; //the input data seed

				Thread.currentThread().setPriority(Thread.MAX_PRIORITY); //reduce random spikes

				byte[] in = new byte[payloadSize];

				SecureRandom gen = new SecureRandom();

				long totalBytes = 0L,
					 totalElapse = 0L;
				int n = 1000;
				while (true) {
					gen.setSeed(randomSeed);
					
					long bytes = in.length*n;
					
					List<Bytes> messages = new ArrayList<Bytes>();
					List<BLSPublicKey> pubKeys = new ArrayList<BLSPublicKey>();
					List<BLSSignature> s = new ArrayList<BLSSignature>();
					
					for(int i=0;i<n;i++) {
						gen.nextBytes(in);
					    Bytes m = Bytes.wrap(in);
					    messages.add(m);
					    BLSKeyPair keyPair = BLSTestUtil.randomKeyPair(1);
						BLSSignature sign = BLS.sign(keyPair.getSecretKey(), m);
						s.add(sign);
						pubKeys.add(keyPair.getPublicKey());
					}
					
					BLSSignature aggregatedSign = BLS.aggregate(s);
					
					long begin = System.nanoTime();
					
					BLS.aggregateVerify(pubKeys, messages, aggregatedSign);

					long end = System.nanoTime();
					long elapse = end - begin;

					totalBytes += bytes;
					totalElapse += elapse;

					System.out.println(payloadSize + " (rand=" + gen.getAlgorithm() + "[seed=" + randomSeed + "]" + ")" + "  \t  " + "cur: " + toString(bytes, elapse) + "  \t  " + "avg: " + toString(totalBytes, totalElapse));
				}
			}

}
