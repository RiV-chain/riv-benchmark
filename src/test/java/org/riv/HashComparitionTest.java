package org.riv;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.NumberFormat;

import org.junit.Test;

import com.joemelsha.crypto.hash.Keccak;
import com.joemelsha.crypto.hash.SHA3;

import io.github.rctcwyvrn.blake3.Blake3;
import junit.framework.TestCase;

public class HashComparitionTest extends TestCase {
	
	private static final byte[] testBytes = "This is a string".getBytes(StandardCharsets.UTF_8);
	
    @Test
    public void test(){
        
    	org.spongycastle.crypto.digests.KeccakDigest kd = new org.spongycastle.crypto.digests.KeccakDigest(256);
        kd.update(testBytes, 0, testBytes.length);
        byte[] output = new byte[32];
		kd.doFinal(output, 0);
    	
    	
    	Blake3 hasher = Blake3.newInstance();
        hasher.update(testBytes);
        assertEquals("718b749f12a61257438b2ea6643555fd995001c9d9ff84764f93f82610a780f2", hasher.hexdigest());
		
		
		final Keccak k = new Keccak(256);
		k.update(testBytes);
		output = k.digest(32).array();
    }
    
    public static void main(String[] args) throws Throwable {
    	
    	

		int payloadSize = 100 * 1024; // input data size
		boolean nativeMemory = true; //whether or not to use native memory buffers
		//Keccak hash = new SHA3(256); //Keccak, SHA3, or SHAKE
		//org.spongycastle.crypto.digests.KeccakDigest hash = new org.spongycastle.crypto.digests.KeccakDigest(256); //Keccak, SHA3, or SHAKE
		//MessageDigest hash = HashUtil.getDigest();
		Blake3 hash = Blake3.newInstance();
		//int digestSize = hash.digestSize(); //if you are using SHAKE, you could set this to anything.
		int digestSize = new SHA3(256).digestSize(); //if you are using SHAKE, you could set this to anything.
		long randomSeed = 13636363L; //the input data seed

		Thread.currentThread().setPriority(Thread.MAX_PRIORITY); //reduce random spikes

		byte[] in = new byte[payloadSize];
		byte[] out = new byte[digestSize];
		SecureRandom gen = new SecureRandom();

		long totalBytes = 0L,
			 totalElapse = 0L;
		while (true) {
			gen.setSeed(randomSeed);
			gen.nextBytes(in);

			long bytes = in.length;

			long begin = System.nanoTime();
			hash.update(in);
			out = hash.digest();
			//hash.reset();
			long end = System.nanoTime();
			long elapse = end - begin;

			totalBytes += bytes;
			totalElapse += elapse;

			System.out.println(payloadSize + " (rand=" + gen.getAlgorithm() + "[seed=" + randomSeed + "]" + ")" + " => " + hash.toString() + " (native=" + nativeMemory + ")" + " => " + digestSize  + "  \t  " + "cur: " + toString(bytes, elapse) + "  \t  " + "avg: " + toString(totalBytes, totalElapse));
		}
	}

	private static String toString(long bytes, long elapseNS) {
		double elapseS = elapseNS / (1000000.0 * 1000.0);
		double bytesM = bytes / (1024.0 * 1024.0);
		double mbs = bytesM / elapseS;
		return NumberFormat.getNumberInstance().format(mbs) + " MB/s";
	}

}
