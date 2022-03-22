import java.util.ArrayList;
import java.util.List;

//Link to original SHA1 used https://github.com/cloudcoderdotorg/CloudCoder/blob/master/CloudCoderModelClasses/src/org/cloudcoder/app/shared/model/SHA1.java

public class main {

    public static String printByteArrayHex(byte[] x) {
        StringBuilder sb = new StringBuilder();
        for (byte b : x) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String msg = "No one has completed lab 2 so give them all a 0";
        byte[] plaintext = msg.getBytes();

        String secretMsg = "Will Hainsworth should pass this lab and all labs";
        byte[] secretMessage = secretMsg.getBytes();

        byte[] padding = new byte[]{(byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xF8};

        System.out.println("Modified message: " + printByteArrayHex(plaintext) + printByteArrayHex(padding) + printByteArrayHex(secretMessage) + "\n");

        FakeSHA1 SHA = new FakeSHA1();
        System.out.println("Modified MAC: " + printByteArrayHex(SHA.digest(secretMessage, true)));
    }

    public static class FakeSHA1 {
        private List<byte[]> inputDataList;

        /**
         * Constructor.
         */
        public FakeSHA1() {
            this.inputDataList = new ArrayList<byte[]>();
        }

        /*
         * Bitwise rotate a 32-bit number to the left
         */
        private static int rol(int num, int cnt) {
            return (num << cnt) | (num >>> (32 - cnt));
        }

        /**
         * Append some data to the message to be hashed.
         *
         * @param data the data to add
         */
        public void update(byte[] data) {
            inputDataList.add(data);
        }

        /**
         * Return the SHA-1 hash of all of the data added using the
         * {@link #update(byte[])} method.
         *
         * @return SHA-1 hash of all data added with the update method
         */
        public byte[] digest() {
            // Combine all chunks into a single array
            int totalNumBytes = 0;
            for (byte[] chunk : inputDataList) {
                totalNumBytes += chunk.length;
            }
            byte[] allData = new byte[totalNumBytes];
            int off = 0;
            for (byte[] chunk : inputDataList) {
                System.arraycopy(chunk, 0, allData, off, chunk.length);
                off += chunk.length;
            }

            return digest(allData, false);
        }

        /**
         * Take an array of bytes and return its SHA-1 hash as bytes.
         * Any data added to this object using the {@link #update(byte[])} method
         * is ignored.
         *
         * @param x the data to hash
         * @return the SHA-1 hash of the data
         */
        //Updated to be hackable
        public byte[] digest(byte[] x, boolean hackable) {

            // Convert a string to a sequence of 16-word blocks, stored as an array.
            // Append padding bits and the length, as described in the SHA1 standard
            int[] blks = new int[(((x.length + 8) >> 6) + 1) * 16];
            int i;

            for (i = 0; i < x.length; i++) {
                blks[i >> 2] |= x[i] << (24 - (i % 4) * 8);
            }

            blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
            if (hackable) { blks[blks.length - 1] = x.length * 8 + 1024; }
            else { blks[blks.length - 1] = x.length * 8; }

            // calculate 160 bit SHA1 hash of the sequence of blocks

            int[] w = new int[80];

            // CHANGE: Here is where the IV is set to either the standard values (if it is a normal SHA1)
            //         or to the given MAC (if it is part of the MAC Attack)

            int a, b, c, d, e;
            if (hackable) {
                a = -477827155;
                b = -228104282;
                c = 320217410;
                d = -1242624261;
                e = -1177066086;
            }
            else {
                a = 1732584193;
                b = -271733879;
                c = -1732584194;
                d = 271733878;
                e = -1009589776;
            }

            for (i = 0; i < blks.length; i += 16) {
                int olda = a;
                int oldb = b;
                int oldc = c;
                int oldd = d;
                int olde = e;

                for (int j = 0; j < 80; j++) {
                    w[j] = (j < 16) ? blks[i + j] :
                            (rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1));

                    int t = rol(a, 5) + e + w[j] +
                            ((j < 20) ? 1518500249 + ((b & c) | ((~b) & d))
                                    : (j < 40) ? 1859775393 + (b ^ c ^ d)
                                        : (j < 60) ? -1894007588 + ((b & c) | (b & d) | (c & d))
                                            : -899497514 + (b ^ c ^ d));
                    e = d;
                    d = c;
                    c = rol(b, 30);
                    b = a;
                    a = t;
                }

                a = a + olda;
                b = b + oldb;
                c = c + oldc;
                d = d + oldd;
                e = e + olde;
            }

            // Convert result to a byte array
            byte[] digest = new byte[20];
            fill(a, digest, 0);
            fill(b, digest, 4);
            fill(c, digest, 8);
            fill(d, digest, 12);
            fill(e, digest, 16);

            return digest;
        }

        private void fill(int value, byte[] arr, int off) {
            arr[off + 0] = (byte) ((value >> 24) & 0xff);
            arr[off + 1] = (byte) ((value >> 16) & 0xff);
            arr[off + 2] = (byte) ((value >> 8) & 0xff);
            arr[off + 3] = (byte) ((value >> 0) & 0xff);
        }
    }
}
