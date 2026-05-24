import javax.swing.*;
import javax.swing.JOptionPane;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.UIManager;
import javax.swing.filechooser.*;
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.GZIPInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

@SuppressWarnings("serial")
public class UIDecryption extends JFrame {
	
    public UIDecryption() {
        initComponents();
        setLocationRelativeTo(null);
    }

    public class filechooser{
		JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
      	
        public String encryptfileName(){
            FileNameExtensionFilter filter = new FileNameExtensionFilter("Encrypted Files", "encrypt");
            jfc.setFileFilter(filter);
            int returnValue = jfc.showOpenDialog(null);

            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = jfc.getSelectedFile();
                return selectedFile.getAbsolutePath();
            }
            return null;
        }
        
        public String signfileName(){
            FileNameExtensionFilter filter = new FileNameExtensionFilter("Signature Files", "signed");
            jfc.setFileFilter(filter);
            int returnValue = jfc.showOpenDialog(null);

            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = jfc.getSelectedFile();
                return selectedFile.getAbsolutePath();
            }
            return null;
        }
	}
    
    private void initComponents() {
        // UI initialization code (same as original, omitted for brevity)
        // ... keep all the GUI setup code unchanged ...
    }
    
	private void Reset(){
	    encryptFileName.setText("");
	    signFileName.setText("");
	    btnUploadEncrypt.setEnabled(true);
	    btnUploadSign.setEnabled(true);
	    publicKeyR.setText("");
	    publicKeyS.setText("");
	    decryptedFile.setText("");
	    btnDecrypt.setEnabled(true);
	    btnReset.setEnabled(true);
	}

    private void btnUploadEncryptActionPerformed(java.awt.event.ActionEvent evt) {
        filechooser f= new filechooser();
        String st=f.encryptfileName();
        encryptFileName.setText(st);
        try{
    	  	RSAPublicKey publicKey = readPublicKey("publicR.rsa");
    		publicKeyR.setText(publicKey.toString());
    		publicKey = readPublicKey("publicS.rsa");
    		publicKeyS.setText(publicKey.toString());
    	}catch(Exception e){
            JOptionPane.showMessageDialog(null,"KEYS NOT FOUND!!! GENERATE KEYS!!!");
    		e.printStackTrace();
    	}
    }
    
    private void btnUploadSignActionPerformed(java.awt.event.ActionEvent evt) {
        filechooser f= new filechooser();
        String st=f.signfileName();
        signFileName.setText(st);
        try{
        	RSAPublicKey publicKey = (RSAPublicKey) readPublicKey("publicR.rsa");
    		publicKeyR.setText(publicKey.toString());
    		publicKey = (RSAPublicKey) readPublicKey("publicS.rsa");
    		publicKeyS.setText(publicKey.toString());
    	}catch(Exception e){
            JOptionPane.showMessageDialog(null,"KEYS NOT FOUND!!! GENERATE KEYS!!!");
    		e.printStackTrace();
    	}
    }

    private void btnDecryptActionPerformed(java.awt.event.ActionEvent evt) {
    	try{
    		long startTime = System.currentTimeMillis();
    		
    		String encryptFile = encryptFileName.getText();
    		String signFile = signFileName.getText();
    		
    		FileInputStream cipherfile = new FileInputStream(encryptFile);
            byte[] cipherText = new byte[cipherfile.available()];
            cipherfile.read(cipherText);
            cipherfile.close();
    		
        	RSAPublicKey rsapub = (RSAPublicKey) readPublicKey("publicS.rsa");
		    BigInteger E = rsapub.getPublicExponent();
		    BigInteger N = rsapub.getModulus();
		    
		    if(Verify(E, N, signFile)){
            	RSAPrivateKey privateKey = readPrivateKey("privateR.rsa");
	        	decrypt(cipherText, privateKey, stripExtension(signFile));
	        	decryptedFile.setText(stripExtension(signFile));
	        	
	        	long endTime = System.currentTimeMillis();
	        	long duration = endTime - startTime;
	        	
      		    JOptionPane.showMessageDialog(null, 
      		    	"Decrypted Successfully!\n" +
      		    	"Original size: " + new File(stripExtension(signFile)).length() + " bytes\n" +
      		    	"Time: " + duration + "ms",
      		    	"Success", JOptionPane.INFORMATION_MESSAGE);
		    }
		    else{
		    	JOptionPane.showMessageDialog(null,"Decryption Unsuccessful! File not verified!!!");
		    }
		
    	}catch(Exception e){
    		JOptionPane.showMessageDialog(null,"Decryption Unsuccessful!!!");
    		e.printStackTrace();
    	}		    
    }
    
    /**
     * Decompress data using GZIP
     */
    public static byte[] decompressData(byte[] data) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        GZIPInputStream gzip = new GZIPInputStream(bis);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        byte[] buffer = new byte[1024];
        int len;
        while ((len = gzip.read(buffer)) != -1) {
            bos.write(buffer, 0, len);
        }
        gzip.close();
        return bos.toByteArray();
    }
    
    /**
     * Decrypt data with chunking support and automatic decompression detection
     */
    public static void decrypt(byte[] text, PrivateKey key, String decryptedFile) {
    	byte[] temp = new byte[LIMIT];
    	byte[] temp1 = new byte[LIMIT];
    	long i = 0, k = 0;
    	ByteArrayOutputStream decryptedDataStream = new ByteArrayOutputStream();
    	
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            
            if(text.length <= LIMIT){
                temp1 = cipher.doFinal(text);
                decryptedDataStream.write(temp1);
            }
            else{
                while(i != text.length){
             	    for(int j = 0 ; j < LIMIT && i != text.length; j++, i++){
         			    temp[j] = text[(int) i];
             	    }        		 
         		    temp1 = cipher.doFinal(temp);
         		    decryptedDataStream.write(temp1);
                    k++;
                    System.out.println("Chunk " + k + " decrypted");
                    temp = new byte[LIMIT];
                }
            }
            
            byte[] decryptedData = decryptedDataStream.toByteArray();
            
            // Try to decompress - if it fails, save raw data
            byte[] finalData = decryptedData;
            try {
                finalData = decompressData(decryptedData);
                System.out.println("Data decompressed successfully");
                System.out.println("Original size: " + decryptedData.length + " -> " + finalData.length);
            } catch (Exception e) {
                System.out.println("Data not compressed, saving as-is");
            }
            
            // Save final data
            FileOutputStream fos = new FileOutputStream(decryptedFile);
            fos.write(finalData);
            fos.close();
            
            System.out.println("Decrypted file saved: " + decryptedFile + " (" + finalData.length + " bytes)");
     
        } catch (Exception ex) {
            System.err.println("Decryption error: ");
            ex.printStackTrace();
        }
    }
    
    private static RSAPublicKey readPublicKey(String filename){
    	try{
    		FileInputStream file = new FileInputStream(filename);
	        byte[] bytes = new byte[file.available()];
	        file.read(bytes);
	        file.close();
	        X509EncodedKeySpec pubspec = new X509EncodedKeySpec(bytes);
	        KeyFactory factory = KeyFactory.getInstance("RSA");
	        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(pubspec);
	        return publicKey;
    	}catch(Exception e){
    		return null;
    	}
    }
    
    public static RSAPrivateKey readPrivateKey(String filename) throws Exception {
        FileInputStream file = new FileInputStream(filename);
        byte[] bytes = new byte[file.available()];
        file.read(bytes);
        file.close();
        PKCS8EncodedKeySpec privspec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privkey = (RSAPrivateKey) factory.generatePrivate(privspec);
        return privkey;
    }

    private void btnResetActionPerformed(java.awt.event.ActionEvent evt) {
        Reset();
    }

    public static void main(String args[]) {
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Metal".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | 
                 UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(UIDecryption.class.getName())
                .log(java.util.logging.Level.SEVERE, null, ex);
        }
        
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new UIDecryption().setVisible(true);
            }
        });
    }

    public static boolean Verify(BigInteger E, BigInteger N, String file){
        try{
            ObjectInputStream rsaObj = new ObjectInputStream(new FileInputStream(file));
            BigInteger dec = (BigInteger)rsaObj.readObject();
            BigInteger blah = (BigInteger)rsaObj.readObject();
            BigInteger encrypt = dec.modPow(E, N);
            rsaObj.close();
            
            if(encrypt.compareTo(blah) == 0)
                return true;
            else
                return false;        
            }catch(Exception e){
            	JOptionPane.showMessageDialog(null,"File: " + file + " not found\nDecryption Unsuccessful!!!");
                return false;
            }
    }

    public static String stripExtension(String str) {
        if (str == null) return null;
        int pos = str.lastIndexOf(".");
        if (pos == -1) return str;
        return str.substring(0, pos);
    }

    // Variables declaration (keep from original)
    private JButton btnUploadEncrypt;
    private JButton btnUploadSign;
    public JButton btnDecrypt;
    private JButton btnReset;
    private JLabel jLabel1;
    private JLabel jLabel2;
    private JLabel jLabel3;
    private JLabel jLabel4;
    private JLabel jLabel5;
    private JPanel jPanel1;
    private JPanel jPanel2;
    public JTextField encryptFileName;
    public JTextField signFileName;
    public JTextField publicKeyR;
    public JTextField publicKeyS;
    public JTextField decryptedFile;
  
    public static final String ALGORITHM = "RSA/ECB/PKCS1PADDING";
  	public static final int LIMIT = 256;
}