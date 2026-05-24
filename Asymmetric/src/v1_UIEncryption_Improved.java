import javax.swing.*;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileSystemView;
import javax.swing.UIManager;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.GZIPOutputStream;
import java.util.zip.GZIPInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;

@SuppressWarnings("serial")
public class UIEncryption extends JFrame {
	
    public UIEncryption() {
        initComponents();
        setLocationRelativeTo(null);
    }

	public class filechooser{
		JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

		public String fileName(){
			int returnValue = jfc.showOpenDialog(null);

			if (returnValue == JFileChooser.APPROVE_OPTION) {
				File selectedFile = jfc.getSelectedFile();
				String st=selectedFile.getAbsolutePath();
				return st;
			}
			return null;
		}
	}
    
    private void initComponents() {

        jPanel1 = new JPanel();
        jPanel2 = new JPanel();

        jLabel1 = new JLabel();
        jLabel2 = new JLabel();
        jLabel3 = new JLabel();
        jLabel4 = new JLabel();
        jLabel5 = new JLabel();

        fileName = new JTextField();
        publicKeyR = new JTextField();
        publicKeyS = new JTextField();
        encryptedFile = new JTextField();
        compressionLabel = new JLabel();

        btnUpload = new JButton();
        btnEncrypt = new JButton();
        btnReset = new JButton();
        chkCompress = new JCheckBox();
        

        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Encryption");
        setResizable(false);

        jPanel1.setBorder(BorderFactory.createTitledBorder("Encryption Menu"));

        jLabel1.setText("Original File Name");

        jLabel2.setText("Sender Public Key");

        jLabel3.setText("Receiver Public Key");

        jLabel4.setText("Encrypted File Name");
        
        jLabel5.setText("Enable Compression:");
        chkCompress.setSelected(true);
        
        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4)
                    .addComponent(jLabel5))
                .addGap(50, 50, 50)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(fileName, javax.swing.GroupLayout.DEFAULT_SIZE, 193, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(publicKeyR)
                        .addComponent(publicKeyS)
                        .addComponent(encryptedFile)
                        .addComponent(chkCompress))
                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    	.addGap(33, 33, 33)))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(fileName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(publicKeyR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(publicKeyS, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(encryptedFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(chkCompress))
                .addGap(27, 27, 27)))
                
        );

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        btnUpload.setText("Upload");
        btnUpload.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnUploadActionPerformed(evt);
            }
        });

        btnEncrypt.setText("Encrypt");
        btnEncrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEncryptActionPerformed(evt);
            }
        });
        btnReset.setText("Reset");
        btnReset.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnResetActionPerformed(evt);
            }
        });

       
        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(btnUpload, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnEncrypt, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnReset, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(btnUpload)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnEncrypt)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnReset)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGap(10, 10,10)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(28, 28, 28)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(32, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(25, Short.MAX_VALUE)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(21, 21, 21))
            .addGroup(layout.createSequentialGroup()
                .addGap(34, 34, 34)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }	
    
	private void Reset(){
	    fileName.setText("");
	    btnUpload.setEnabled(true);
	    publicKeyR.setText("");
	    publicKeyS.setText("");
	    encryptedFile.setText("");
	    btnReset.setEnabled(true);
	    btnEncrypt.setEnabled(true);
	    chkCompress.setSelected(true);
	}
    
    private void btnUploadActionPerformed(java.awt.event.ActionEvent evt) {
        filechooser f= new filechooser();
        String st="";
        st = f.fileName();
        fileName.setText(st);
        try{
        	RSAPublicKey pub = readPublicKey("publicR.rsa");
    		publicKeyR.setText(pub.toString());
    		pub = readPublicKey("publicS.rsa");
    		publicKeyS.setText(pub.toString());
    	}catch(Exception e){
    		JOptionPane.showMessageDialog(null, "Keys not found! Please generate keys first.");
    		e.printStackTrace();
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
    
    private void btnEncryptActionPerformed(java.awt.event.ActionEvent evt) {
    	try{
    		long startTime = System.currentTimeMillis();
    		
    		// Read original file
    		FileInputStream plainfile = new FileInputStream(fileName.getText());
            byte[] originalText = new byte[plainfile.available()];
            plainfile.read(originalText);
            plainfile.close();
            
            long originalSize = originalText.length;
            System.out.println("Original file size: " + originalSize + " bytes");
            
            // Compress if enabled
            byte[] dataToEncrypt = originalText;
            if (chkCompress.isSelected()) {
                dataToEncrypt = compressData(originalText);
                System.out.println("Compressed file size: " + dataToEncrypt.length + " bytes");
                System.out.println("Compression ratio: " + 
                    String.format("%.2f%%", (1 - (double)dataToEncrypt.length/originalSize) * 100));
            }
            
    		// Compute hash on original data (before compression)
    		MessageDigest md = MessageDigest.getInstance("SHA-256");
    		md.update(originalText);
        	byte[] byteData = md.digest();
        	BigInteger digest = new BigInteger(1, byteData);
    		
    		// Encrypt compressed data
    	  	RSAPublicKey publicKey = readPublicKey("publicR.rsa");
       		encrypt(dataToEncrypt, publicKey);
       		
       		// Sign digest
       		RSAPublicKey rsapub = (RSAPublicKey) readPublicKey("publicS.rsa");
		    BigInteger N = rsapub.getModulus();
		    
		    RSAPrivateKey rsapriv = readPrivateKey("privateS.rsa");
		    BigInteger D =  rsapriv.getPrivateExponent();
		    
            Sign(D, N, digest, fileName.getText());
      		encryptedFile.setText(ENCRYPTED_FILE);
      		
      		long endTime = System.currentTimeMillis();
      		long duration = endTime - startTime;

    		JOptionPane.showMessageDialog(null, 
    			"Encryption and Signing Successful!\n" +
    			"Original size: " + originalSize + " bytes\n" +
    			"Encrypted size: " + new File(ENCRYPTED_FILE).length() + " bytes\n" +
    			"Time: " + duration + "ms",
    			"Success", JOptionPane.INFORMATION_MESSAGE);
    		
    	}catch(Exception e){
    		JOptionPane.showMessageDialog(null, "Encryption Unsuccessful!");
    		e.printStackTrace();
    	}
    }
    
    /**
     * Compress data using GZIP
     */
    public static byte[] compressData(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPOutputStream gzip = new GZIPOutputStream(bos);
        gzip.write(data);
        gzip.close();
        return bos.toByteArray();
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
     * Encrypt data with chunking support
     */
    public static void encrypt(byte[] originalText, PublicKey key){
        System.out.println("\nEncryption started for " + originalText.length + " bytes");
        byte[] temp = new byte[LIMIT];
        long i = 0, k = 0;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            // File less than 245 bytes
            if(originalText.length <= LIMIT){
                byte[] cipherTemp = cipher.doFinal(originalText);
                FileOutputStream fos = new FileOutputStream(ENCRYPTED_FILE);
                fos.write(cipherTemp);
                fos.close();
                System.out.println("Small file encrypted: " + cipherTemp.length + " bytes");
            }
            // Files larger than 245 bytes
            else{
                while(i < originalText.length){
                	for(int j = 0 ; j < LIMIT && i != originalText.length; j++, i++) {
                		temp[j] = originalText[(int) i];
                	}
                	
                	byte[] encryptedChunk = cipher.doFinal(temp);
                	FileOutputStream fis = new FileOutputStream(k + ".encrypt");
                    ObjectOutputStream oos = new ObjectOutputStream(fis);
        			oos.writeInt(encryptedChunk.length);  // Store length for proper reconstruction
        			oos.write(encryptedChunk);
        			oos.close();
                	
                	System.out.println("Chunk " + k + " encrypted: " + encryptedChunk.length + " bytes");
                	k++;
                	temp = new byte[LIMIT];
            	}
                
                // Combine all encrypted chunks
                FileOutputStream finalOutput = new FileOutputStream(ENCRYPTED_FILE);
                int fileNo = 0;
                while(fileNo < k){
	                FileInputStream chunkFile = new FileInputStream(fileNo + ".encrypt");
	                byte[] chunkData = new byte[chunkFile.available()];
	                chunkFile.read(chunkData);
	                chunkFile.close();
	                
	                File file = new File(fileNo + ".encrypt");
	                file.delete();
	                
	                finalOutput.write(chunkData);
	                fileNo++;
                }
                finalOutput.close();
                System.out.println("All chunks combined into " + ENCRYPTED_FILE);
            }
        }catch (Exception e) {
            System.err.println("Encryption error: ");
            e.printStackTrace();
        }
    }

    private void btnResetActionPerformed(java.awt.event.ActionEvent evt) {
        Reset();
    }

    public static void main(String args[]) throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
       
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Metal".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(UIEncryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(UIEncryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(UIEncryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(UIEncryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new UIEncryption().setVisible(true);
            }
        });
    }

    public static void Sign(BigInteger D, BigInteger N, BigInteger digest, String file){
        try{
            BigInteger decrypt = digest.modPow(D, N);
            FileOutputStream fos = new FileOutputStream(file + ".signed");
            ObjectOutputStream signed = new ObjectOutputStream(fos);
            signed.writeObject(decrypt);
            signed.writeObject(digest);
            signed.close();
        }
        catch(Exception e){
        	JOptionPane.showMessageDialog(null, "File: " + file + ".signed was not created");
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

    public static String stripExtension(String str) {
        if (str == null) return null;
        int pos = str.lastIndexOf(".");
        if (pos == -1) return str;
        return str.substring(0, pos);
    }
        
    // Variables declaration
    private JButton btnUpload;
    public JButton btnEncrypt;
    public JButton btnReset;
    private JCheckBox chkCompress;
    
    private JLabel jLabel1;
    private JLabel jLabel2;
    private JLabel jLabel3;
    private JLabel jLabel4;
    private JLabel jLabel5;
    private JLabel compressionLabel;
    
    private JPanel jPanel1;
    private JPanel jPanel2;
    
    public JTextField fileName;
    public JTextField publicKeyR;
    public JTextField publicKeyS;
    public JTextField encryptedFile;
    
    public static final int LIMIT = 245;
 	public static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
 	public static final String ENCRYPTED_FILE = "cipherText.encrypt";
    // End of variables declaration
}