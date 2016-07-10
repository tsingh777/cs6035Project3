import java.io.IOException;
import java.io.FileNotFoundException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;

public class task1 {


    public static byte[] cbc_encrypt(byte[] message, byte[] key, byte[] iv) {

        ArrayList splitMessage = new ArrayList();

        //get the true key and iv
        byte[] realIV = getKeyIVFromFileBytes(iv);
        byte[] realKey = getKeyIVFromFileBytes(key);

        //Split the message into 64 bit arrays
        splitMessage(splitMessage, message);

        //Add the Padding
        if (message.length % 8 == 0) {
            byte[] temp = {
                    (byte) 0x80, // 1000 0000 in hex (first padding byte
                    (byte) 0x0, // 0000 0000 in hex (1 byte of 0s)
                    (byte) 0x0,
                    (byte) 0x0,
                    (byte) 0x0,
                    (byte) 0x0,
                    (byte) 0x0,
                    (byte) 0x0};
            splitMessage.add(temp);
        } else {
            byte[] lastItem = (byte[]) splitMessage.get(splitMessage.size() - 1);
            byte[] temp = new byte[8];
            int start = lastItem.length;
            for (int i = 0; i < 8; i++) {
                if (i < start) {
                    temp[i] = lastItem[i];
                } else if (i == start) {
                    temp[i] = (byte) 0x80;
                } else {
                    temp[i] = (byte) 0x0;
                }
            }
            splitMessage.set(splitMessage.size() - 1, temp);
        }


        DES des = new DES();
        Object k;
        byte[] output = new byte[splitMessage.size() * 8];

        try {
            k = des.makeKey(realKey, des.KEY_SIZE);
            byte[] cipher = realIV;
            for (int i = 0, j = i; i < splitMessage.size(); i++) {
                byte[] input = (byte[]) splitMessage.get(i);

                //XOR the cipher and the input;

                for (int x = 0; x < 8; x++) {
                    input[x] = (byte) (cipher[x] ^ input[x]);
                }

                String sOutput = des.encrypt(k, input);
                cipher = Util.toBytesFromString(sOutput);
                System.arraycopy(cipher, 0, output, 8 * j++, cipher.length);
            }

            return output;
        } catch (InvalidKeyException e) {
            System.out.println("Invalid Key.");
        }
        return null;
    }

    static byte hexStringToByteArray(String s) {
        int len = s.length();
        byte data = 0;
        for (int i = 0; i < len; i += 2) {
            data = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    static byte[] getKeyIVFromFileBytes(byte[] input) {
        byte[] output = new byte[8];
        for (int i = 0, j = i; i < 8; i++) {
            char first = (char) input[j++];
            char second = (char) input[j++];
            output[i] = hexStringToByteArray("" + first + second);
        }
        return output;
    }

    static void splitMessage(ArrayList list, byte[] input) {
        for (int i = 0; i < input.length; i += 8) {
            byte[] temp;
            temp = Arrays.copyOfRange(input, i, i + 8);
            if (i + 8 < input.length) {
                temp = Arrays.copyOfRange(input, i, i + 8);
            } else {
                temp = Arrays.copyOfRange(input, i, input.length);
            }
            list.add(temp);
        }
    }

    public static byte[] cbc_decrypt(byte[] message, byte[] key, byte[] iv) {

        ArrayList splitMessage = new ArrayList();

        //get the true key and iv
        byte[] realIV = getKeyIVFromFileBytes(iv);
        byte[] realKey = getKeyIVFromFileBytes(key);

        //Split the message into 64 bit arrays
        splitMessage(splitMessage, message);

        DES des = new DES();
        Object k;
        byte[] output = new byte[splitMessage.size() * 8];

        try {
            k = des.makeKey(realKey, des.KEY_SIZE);
            byte[] cipher;
            byte[] plainText;
            byte[] padding = new byte[8];
            int lastEight = 0;
            for (int i = splitMessage.size() - 1, j = output.length - 8; i >= 0; i--, j -= 8) {
                byte[] input = (byte[]) splitMessage.get(i);

                //XOR the cipher and the input;

                String sOutput = des.decrypt(k, input);
                if (i > 0) {
                    cipher = (byte[]) splitMessage.get(i - 1);
                } else {
                    cipher = realIV;
                }
                plainText = Util.toBytesFromString(sOutput);
                for (int x = 0; x < 8; x++) {
                    plainText[x] = (byte) (cipher[x] ^ plainText[x]);
                }
                System.arraycopy(plainText, 0, output, j, plainText.length);
                if (i == splitMessage.size() - 1) {
                    lastEight = j;
                    System.arraycopy(plainText, 0, padding, 0, plainText.length);
                }
            }

            //removed the padding
            if (padding[0] == -128) {
                //message was multiple multiple of 8 bytes.
                output = Arrays.copyOfRange(output, 0, lastEight);
            } else {
                int index = 0;
                for (int i = 0; i < padding.length; i++) {
                    if (padding[i] == -128) {
                        index = i;
                    }
                }
                output = Arrays.copyOfRange(output, 0, lastEight + index);
            }

            return output;
        } catch (InvalidKeyException e) {
            System.out.println("Invalid Key.");
        }
        return null;
    }

    public static void main(String[] args) {
        if (args.length != 5) {
            System.out.println("Wrong number of arguments!\njava task1 $MODE $INFILE $KEYFILE $IVFILE $OUTFILE.");
            System.exit(1);
        } else {
            String mode = args[0];
            String infile = args[1];
            String keyfile = args[2];
            String ivfile = args[3];
            String outfile = args[4];
            byte[] input = readFromFile(infile);
            byte[] key = readFromFile(keyfile);
            byte[] iv = readFromFile(ivfile);
            byte[] output = null;

            double start = getCpuTime();
            // Calculate the CPU cycles.
            if (mode.equals("enc")) {
                output = cbc_encrypt(input, key, iv);
            } else if (mode.equals("dec")) {
                output = cbc_decrypt(input, key, iv);
            } else {
                System.out.println(mode);
                System.out.println("Wrong mode!");
                System.exit(1);
            }
            double end = getCpuTime();
            System.out.printf("Consumed CPU time=%f\n", end - start);
            writeToFile(outfile, output);
        }
    }

    static byte[] readFromFile(String path) {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(path));
            return encoded;
        } catch (IOException e) {
            System.out.println("File Not Found.");
            return null;
        }
    }

    static void writeToFile(String path, byte[] data) {
        try {
            Files.write(Paths.get(path), data);
        } catch (FileNotFoundException e) {
            System.out.println("File Not Found.");
        } catch (IOException e) {
            System.out.println("File Not Found.");
        }
    }

    // Helper functions.
    private static double getCpuTime() {
        ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        // getCurrentThreadCpuTime() returns the total CPU time for the current thread in nanoseconds.
        return bean.isCurrentThreadCpuTimeSupported() ? ((double) bean.getCurrentThreadCpuTime() / 1000000000) : 0L;
    }

    static void testDES(String key, String message) {
        DES des = new DES();
        Object k;
        try {
            k = des.makeKey(key.getBytes(), des.KEY_SIZE);
            String output = des.encrypt(k, message.getBytes());
            // suppress output
            System.out.println(output);
        } catch (InvalidKeyException e) {
            System.out.println("Invalid Key.");
        }
    }

    static void test() {
        // This function is for test and illustration purpose.
        char[] chars1 = new char[8];
        char[] chars2 = new char[8];
        Arrays.fill(chars1, '\0');
        Arrays.fill(chars2, '\0');
        String key = new String(chars1);
        String message = new String(chars2);
        testDES(key, message);
        chars2[7] = '\1';
        message = new String(chars2);
        testDES(key, message);
        chars1[7] = '\2';
        chars2[7] = '\0';
        key = new String(chars1);
        message = new String(chars2);
        testDES(key, message);
        chars2[7] = '\1';
        message = new String(chars2);
        testDES(key, message);
    }

    static void printByteArray(byte[] a) {
        for (int j = 0; j < a.length; j++) {
            System.out.print("[" + a[j] + "]\t");
        }
        System.out.print('\n');
    }

    static void prettyPrint(byte[] message) {
        for (int i = 0, j = 7; i < message.length; i++) {
            System.out.print("[" + message[i] + "]\t");
            if (i == j) {
                System.out.print("\n");
                j += 8;
            }
        }
    }

    static void printSplit(ArrayList<byte[]> a) {
        for (byte[] i : a) {
            for (int j = 0; j < i.length; j++) {
                System.out.print("[" + i[j] + "]\t\t");
            }
            System.out.print('\n');
        }
        System.out.print("\n");
    }
}
