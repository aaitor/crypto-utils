package com.github.aaitor.crypto.utils.helpers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public abstract class FilesHelper {

    /**
     * Read all the bytes of a file
     * @param filePath full path to the file to read
     * @return file contents in bytes
     * @throws IOException
     */
    public static byte[] readFileBytes(String filePath) throws IOException {

        // Read all the public key bytes
        Path path = Paths.get(filePath);
        return Files.readAllBytes(path);
    }

}
