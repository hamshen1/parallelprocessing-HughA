import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;

public class ZipPasswordCracker {
    // Path to the password protected ZIP file
    private static final String ZIP_PATH = "myArchiveTwo.zip";
    // Character set to try. Here we just use digits for simplicity.
    private static final char[] CHARSET = "0123456789".toCharArray();
    // Max password length to try
    private static final int MAX_LENGTH = 5;

    public static void main(String[] args) {
        boolean found = false;

        for (int length = 1; length <= MAX_LENGTH && !found; length++) {
            found = tryAllCombinations("", length);
        }

        if (!found) {
            System.out.println("No password found up to length " + MAX_LENGTH);
        }
    }

    /**
     * Recursively tries all combinations of the given length from the CHARSET.
     * @param prefix current prefix
     * @param length total length of the password to try
     * @return true if found, false otherwise
     */
    private static boolean tryAllCombinations(String prefix, int length) {
        if (prefix.length() == length) {
            // We have a candidate password of the correct length.
            if (checkPassword(prefix)) {
                System.out.println("Password found: " + prefix);
                // Once found, extract the files
                try {
                    ZipFile zipFile = new ZipFile(ZIP_PATH, prefix.toCharArray());
                    zipFile.extractAll(".");
                    System.out.println("Files extracted successfully!");
                } catch (ZipException e) {
                    System.err.println("Extraction failed even after password match (unexpected): " + e.getMessage());
                }
                return true;
            }
            return false;
        }

        for (char c : CHARSET) {
            if (tryAllCombinations(prefix + c, length)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Attempts to open and extract a file from the ZIP with the given candidate password.
     * If extraction succeeds, the password is correct.
     * @param candidate the password to check
     * @return true if the password is correct, false otherwise
     */
    private static boolean checkPassword(String candidate) {
        try {
            ZipFile zipFile = new ZipFile(ZIP_PATH, candidate.toCharArray());
            // Attempting extraction as a password check:
            // If the password is wrong, this will throw ZipException.
            // We'll extract to a temporary location first to avoid clutter.
            // But to avoid unnecessary overhead, just extract to a dummy path and delete it.
            // Instead, let's just try to open a stream or do a minimal operation.
            
            // If you don't want to extract each time, just attempt to read a file header:
            // However, file headers are not encrypted, so let's try extracting a single file:
            
            // Get a specific file header (we know 'answer.txt' should be there)
            if (zipFile.getFileHeader("answer.txt") == null) {
                // If for some reason the file isn't there, return false
                return false;
            }
            // Try extracting just this file to a temp directory (in-memory is not supported)
            // A wrong password will cause an exception here
            zipFile.extractFile("answer.txt", "tempCheck");
            
            // If we reached here, extraction succeeded. Delete the temp file after checking.
            java.io.File tempDir = new java.io.File("tempCheck/answer.txt");
            if (tempDir.exists()) {
                tempDir.delete();
                // Delete the temp directory
                new java.io.File("tempCheck").delete();
            }
            
            return true;
        } catch (ZipException e) {
            // Wrong password or other error
            return false;
        }
    }
}
