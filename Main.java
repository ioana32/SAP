import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        String targetHashBase64 = "Mr7HA6zWAw2NVXL0BKdVsKZWaKjif9HwpmO2BlSt9GA=";
        String directoryPath = "Directorul unde cauti fisierul .user";

        File directory = new File(directoryPath);
        File foundFile = searchUserFile(directory, targetHashBase64);

        if (foundFile != null) {
            System.out.println("Found file: " + foundFile.getName());
        } else {
            System.out.println("File not found.");
        }
    }

    private static File searchUserFile(File directory, String targetHashBase64) {
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile() && file.getName().toLowerCase().endsWith(".user")) {
                    String hash = calculateSHA256(file);
                    if (targetHashBase64.equals(hash)) {
                        return file;
                    }
                }
            }
        }
        return null;
    }

    private static String calculateSHA256(File file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(file);
            byte[] byteArray = new byte[1024];
            int bytesCount;
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
            fis.close();
            byte[] bytes = digest.digest();
            return Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
