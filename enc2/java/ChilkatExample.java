import com.chilkatsoft.*;

public class ChilkatExample {

  static {
    try {
        System.loadLibrary("chilkat");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load.\n" + e);
      System.exit(1);
    }
  }

  public static void main(String argv[])
  {
    // This example assumes the Chilkat API to have been previously unlocked.
    // See Global Unlock Sample for sample code.

    CkRsa rsa = new CkRsa();

    CkPrivateKey privKey = new CkPrivateKey();

    boolean success = privKey.LoadPemFile("myPrivateKey.pem");
    if (success != true) {
        System.out.println(privKey.lastErrorText());
        return;
        }

    success = rsa.ImportPrivateKeyObj(privKey);
    if (success != true) {
        System.out.println(rsa.lastErrorText());
        return;
        }

    // Load the encrypted bytes.
    // This will typically be a file that is 128, 256, etc. bytes in length.
    // For example, maybe it is a file containing an encrypted passphrase...
    CkBinData bdEncrypted = new CkBinData();
    success = bdEncrypted.LoadFile("qa_data/passphrase.enc");
    if (success != true) {
        System.out.println("Failed to load file.");
        return;
        }

    // In this case, we know that it was a string that was encrypted,
    // so decryption should result in a string.
    // To make things easy, we'll pass the RSA encrypted data as a Base64 string 
    // to the decryptor.
    rsa.put_EncodingMode("base64");
    String passphrase = rsa.decryptStringENC(bdEncrypted.getEncoded("base64"),true);
    if (rsa.get_LastMethodSuccess() != true) {
        System.out.println(rsa.lastErrorText());
        return;
        }

    System.out.println("Decrypted passphrase: " + passphrase);
  }
}
