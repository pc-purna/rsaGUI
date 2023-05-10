
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.BitSet;

import javax.crypto.Cipher;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.WindowConstants;
import javax.swing.filechooser.FileSystemView;


@SuppressWarnings("serial")
public class UIEncryption extends JFrame {
	
    public UIEncryption() {
        initComponents();
        setLocationRelativeTo(null);
      }

	public class filechooser{

		JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

			public String fileName(){
				/*FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files", "txt");
				FileNameExtensionFilter filter1 = new FileNameExtensionFilter("PDF Files", "pdf");
				FileNameExtensionFilter filter2 = new FileNameExtensionFilter("Audio Files", "mp3","wav");
				FileNameExtensionFilter filter4 = new FileNameExtensionFilter("Image Files", "jpeg","jpg","png");
				FileNameExtensionFilter filter3 = new FileNameExtensionFilter("Video Files", "mp4","3gp","mpeg","avi","mkv");


				jfc.setFileFilter(filter);
				jfc.setFileFilter(filter1);
				jfc.setFileFilter(filter2);
				jfc.setFileFilter(filter3);
				jfc.setFileFilter(filter4);*/
				

			int returnValue = jfc.showOpenDialog(null);
			// int returnValue = jfc.showSaveDialog(null);

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

        fileName = new JTextField();
        publicKeyR = new JTextField();
        publicKeyS = new JTextField();
        encryptedFile = new JTextField();

        btnUpload = new JButton();
        btnEncrypt = new JButton();
        btnReset = new JButton();
        

        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Encryption");
        setResizable(false);

        jPanel1.setBorder(BorderFactory.createTitledBorder("Encryption Menu"));

        jLabel1.setText("Original File Name");

        jLabel2.setText("Sender Public Key");

        jLabel3.setText("Receiver Public Key");

        jLabel4.setText("Encrypted File Name");
        
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
                    .addComponent(jLabel4))
                .addGap(50, 50, 50)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(fileName, javax.swing.GroupLayout.DEFAULT_SIZE, 193, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(publicKeyR)
                        .addComponent(publicKeyS)
                        .addComponent(encryptedFile))
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
                    .addComponent(encryptedFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
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

	}
    private void btnUploadActionPerformed(java.awt.event.ActionEvent evt) {
        filechooser f= new filechooser();
        String st="";
        st = f.fileName();
        fileName.setText(st);
        try{
        	RSAPublicKey pub = readPublicKey("publicReceiver.rsa");
    		publicKeyR.setText(pub.toString());
    		pub = readPublicKey("publicSender.rsa");
    		publicKeyS.setText(pub.toString());
    	}catch(Exception e){
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
    		
    		MessageDigest md = MessageDigest.getInstance("SHA-256");
    		FileInputStream plainfile = new FileInputStream(fileName.getText());
            byte[] originalText = new byte[plainfile.available()];
            plainfile.read(originalText);
            plainfile.close();
            
    		//byte[] cipherText = new byte[100*originalText.length];
    	  	RSAPublicKey publicKey = readPublicKey("publicReceiver.rsa");
      		//cipherText = encrypt(originalText, publicKey);
      		encrypt(originalText, publicKey);
      		/*FileOutputStream fos = new FileOutputStream(ENCRYPTED_FILE);
			fos.write(cipherText);
			fos.close();*/

			
			md.update(originalText);
        	byte[] byteData = md.digest();
        	BigInteger digest = new BigInteger(1, byteData);
        	
        	RSAPublicKey rsapub = (RSAPublicKey) readPublicKey("publicSender.rsa");
		    BigInteger N = rsapub.getModulus();
		    
		    RSAPrivateKey rsapriv = readPrivateKey("privateSender.rsa");
		    BigInteger D =  rsapriv.getPrivateExponent();
		    

            Sign(D,N,digest,fileName.getText());
      		encryptedFile.setText(ENCRYPTED_FILE);

   
      		JOptionPane.showMessageDialog(null,"Encrypted and Signed Successfully!!! ");
    		
    	}catch(Exception e){
    		JOptionPane.showMessageDialog(null,"Encryption Unsuccessful!!! ");
    		e.printStackTrace();
    	}
        
    }
    public static void encrypt(byte[] originalText, PublicKey key){
    	System.out.println("\n"+BitSet.valueOf(originalText).cardinality());
        byte[] cipherTemp =  new byte[100*originalText.length];
        byte[] temp = new byte[LIMIT];
        long i = 0,k=0;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            //file less than 245 bytes
                if(originalText.length <= LIMIT){
                    cipherTemp = cipher.doFinal(originalText);
                    System.out.println(cipherTemp.length + "\n"+BitSet.valueOf(cipherTemp).cardinality());
                }
            //files larger than 245 bytes
            else{
                while(i<originalText.length){
                	for(int j = 0 ; j < LIMIT && i != originalText.length; j++,i++)
                		temp[j]=originalText[(int) i];
                	
                	temp = cipher.doFinal(temp);
                	FileOutputStream fis = new FileOutputStream(k+".encrypt");
                    ObjectOutputStream signed = new ObjectOutputStream(fis);
        			signed.write(temp);
        			signed.close();
                	System.out.println("temp "+ k++ +" " +BitSet.valueOf(temp).cardinality());
                	
                	System.out.println(BitSet.valueOf(cipherTemp).cardinality());
                	if(i == LIMIT)
                		System.arraycopy(temp, 0, cipherTemp, 0, temp.length);
                	else
                		System.arraycopy(temp, 0, cipherTemp, BitSet.valueOf(cipherTemp).cardinality(), temp.length);
                	temp = new byte[LIMIT];
            	}
                int fileNo=0;
                while(fileNo < k){
	                FileInputStream plainfile = new FileInputStream(fileNo +".encrypt");
	                byte[] cipherText = new byte[plainfile.available()];
	                plainfile.read(cipherText);
	                plainfile.close();
	                File file = new File(fileNo +".encrypt");
	                file.delete();
	                FileOutputStream signed = new FileOutputStream(ENCRYPTED_FILE,true);
	                signed.write(cipherText);
        			signed.close();
        			fileNo++;
                }
                
                /*byte[] cipherText = new byte[100*cipherTemp.length];
                System.arraycopy(cipherTemp, 0, cipherText, 0, BitSet.valueOf(cipherTemp).cardinality());
                cipherTemp = new byte[100*cipherTemp.length];*/
                //return cipherText; 
            }
        }catch (Exception e) {
          e.printStackTrace();
         // return null;
        }
          // return cipherTemp;
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
            public void run() {
                new UIEncryption().setVisible(true);
            }
        });
    }


	/*public static byte[] readFile(String file) throws IOException{
    	BufferedReader br = new BufferedReader(new FileReader(file));
    	try {
	        StringBuilder sb = new StringBuilder();
	        String line = br.readLine();

	        while (line != null) {
	            sb.append(line);
	            sb.append("\n");
	            line = br.readLine();
	        }
	        	return sb;
	    	}finally {
	        	br.close();
    	}
		
    	FileInputStream plainfile = new FileInputStream(file);
        byte[] plaintext = new byte[plainfile.available()];
        plainfile.close();
        return plaintext;
	}	*/




public static void Sign(BigInteger D, BigInteger N, BigInteger digest,String file){
        
            //create the .signed file and prints stuff out
        try{
            BigInteger decrypt = digest.modPow(D, N);
            FileOutputStream fos = new FileOutputStream( file+".signed");
            ObjectOutputStream signed = new ObjectOutputStream(fos);
            signed.writeObject(decrypt);
            signed.writeObject(digest);
            signed.close();
        }
        catch(Exception e){
        	JOptionPane.showMessageDialog(null,"File: " + file + ".signed is not created");
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
        // Handle null case specially.

        if (str == null) return null;

        // Get position of last '.'.

        int pos = str.lastIndexOf(".");

        // If there wasn't any '.' just return the string as is.

        if (pos == -1) return str;

        // Otherwise return the string, up to the dot.

        return str.substring(0, pos);
    }
        
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private JButton btnUpload;
    public JButton btnEncrypt;
    public JButton btnReset;
    
    private JLabel jLabel1;
    private JLabel jLabel2;
    private JLabel jLabel3;
    private JLabel jLabel4;
    private JPanel jPanel1;
    private JPanel jPanel2;
    public JTextField fileName;
    public JTextField publicKeyR;
    public JTextField publicKeyS;
    public JTextField encryptedFile;
    public static final int LIMIT = 245;
 	public static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
 	public static final String ENCRYPTED_FILE = "cipherText.encrypt";
    // End of variables declaration//GEN-END:variables
}