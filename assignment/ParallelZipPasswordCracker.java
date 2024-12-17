import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class ParallelZipPasswordCracker {
    // Path to the password-protected ZIP file
    private static final String ZIP_PATH = "myArchiveTwo.zip";
    // Character set to try
    private static final char[] CHARSET = "0123456789".toCharArray();
    // Max password length to try
    private static final int MAX_LENGTH = 5;
    // Depth cutoff for prefix-based task generation
    private static final int DEPTH_CUTOFF = 2;
    // Shared flag to indicate if the password has been found
    private static final AtomicBoolean found = new AtomicBoolean(false);
    // Variable to store the time when the password is found
    private static volatile long endTime = 0;

    public static void main(String[] args) throws InterruptedException {
        // Dynamically determine the number of threads based on available processors
        final int THREAD_COUNT = Runtime.getRuntime().availableProcessors();
        System.out.println("Using " + THREAD_COUNT + " threads for password cracking.");

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);

        // Record the start time
        long startTime = System.nanoTime();

        // Generate and submit tasks for each password length
        for (int length = 1; length <= MAX_LENGTH && !found.get(); length++) {
            final int currentLength = length; // Make a final copy for the lambda
            if (currentLength < DEPTH_CUTOFF) {
                // Handle shorter lengths directly
                executor.submit(() -> bruteForceRecursive("", currentLength));
            } else {
                // Generate tasks based on prefix depth cutoff
                List<Callable<Void>> tasks = new ArrayList<>();
                generatePrefixTasks("", DEPTH_CUTOFF, currentLength, tasks);

                for (Callable<Void> task : tasks) {
                    if (found.get()) break;
                    executor.submit(task);
                }
            }
        }

        // Shutdown the executor and await termination
        executor.shutdown();
        boolean terminated = executor.awaitTermination(1, TimeUnit.HOURS);

        // Record the end time if not already recorded
        if (endTime == 0) {
            endTime = System.nanoTime();
        }

        // Calculate and display the duration
        long durationNs = endTime - startTime;
        double durationSeconds = durationNs / 1_000_000_000.0;
        System.out.printf("Password cracking completed in %.3f seconds.%n", durationSeconds);

        if (!found.get()) {
            System.out.println("No password found up to length " + MAX_LENGTH);
        }
    }

    /**
     * Generates tasks for all prefixes of a given cutoff length.
     * Each task will handle the remaining password search space from that prefix.
     */
    private static void generatePrefixTasks(String prefix, int depthNeeded, int totalLength, List<Callable<Void>> tasks) {
        if (found.get()) return;
        if (prefix.length() == depthNeeded) {
            tasks.add(() -> {
                tryAllCombinationsFromPrefix(prefix, totalLength);
                return null;
            });
            return;
        }

        for (char c : CHARSET) {
            if (found.get()) return;
            generatePrefixTasks(prefix + c, depthNeeded, totalLength, tasks);
        }
    }

    /**
     * Recursively tries all combinations starting from the given prefix.
     * If the password is found, sets the shared flag and records the end time.
     */
    private static void tryAllCombinationsFromPrefix(String prefix, int totalLength) {
        if (found.get()) return;

        if (prefix.length() == totalLength) {
            if (checkPassword(prefix)) {
                passwordFound(prefix);
            }
            return;
        }

        for (char c : CHARSET) {
            if (found.get()) return;
            tryAllCombinationsFromPrefix(prefix + c, totalLength);
            if (found.get()) return;
        }
    }

    /**
     * Performs brute force search for shorter password lengths directly.
     */
    private static void bruteForceRecursive(String prefix, int length) {
        if (found.get()) return;
        if (prefix.length() == length) {
            if (checkPassword(prefix)) {
                passwordFound(prefix);
            }
            return;
        }

        for (char c : CHARSET) {
            if (found.get()) return;
            bruteForceRecursive(prefix + c, length);
            if (found.get()) return;
        }
    }

    /**
     * Attempts to open and extract a file from the ZIP with the given candidate password.
     * If extraction succeeds, the password is correct.
     */
    private static boolean checkPassword(String candidate) {
        try {
            ZipFile zipFile = new ZipFile(ZIP_PATH, candidate.toCharArray());
            if (zipFile.getFileHeader("answer.txt") == null) {
                return false;
            }
            // Attempt to extract a known file to verify password correctness
            zipFile.extractFile("answer.txt", "tempCheck");
            java.io.File tempFile = new java.io.File("tempCheck/answer.txt");
            boolean result = tempFile.exists();
            // Clean up temporary files
            if (tempFile.exists()) tempFile.delete();
            java.io.File tempDir = new java.io.File("tempCheck");
            if (tempDir.exists()) tempDir.delete();
            return result;
        } catch (ZipException e) {
            // Wrong password or other error
            return false;
        }
    }

    /**
     * Handles actions to perform when the password is found.
     * Records the end time, extracts all files, and sets the shared flag.
     */
    private static void passwordFound(String password) {
        if (found.compareAndSet(false, true)) {
            endTime = System.nanoTime(); // Record the end time
            System.out.println("Password found: " + password);
            extractFiles(password);
        }
    }

    /**
     * Extracts all files from the ZIP once the correct password is found.
     */
    private static void extractFiles(String password) {
        try {
            ZipFile zipFile = new ZipFile(ZIP_PATH, password.toCharArray());
            zipFile.extractAll(".");
            System.out.println("All files extracted successfully!");
        } catch (ZipException e) {
            System.err.println("Extraction failed: " + e.getMessage());
        }
    }
}
