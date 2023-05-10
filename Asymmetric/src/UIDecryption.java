//package asymetricKey;

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
//import java.util.BitSet;


//@SuppressWarnings("serial")
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

        jPanel1 = new JPanel();
        jPanel2 = new JPanel();

        jLabel1 = new JLabel();
        jLabel2 = new JLabel();
        jLabel3 = new JLabel();
        jLabel4 = new JLabel();
        jLabel5 = new JLabel();

        encryptFileName = new JTextField();
        signFileName = new JTextField();
        publicKeyR = new JTextField();
        publicKeyS = new JTextField();
        decryptedFile = new JTextField();

        btnUploadEncrypt = new JButton();
        btnUploadSign = new JButton();
        btnDecrypt = new JButton();
        btnReset = new JButton();
        

        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Decryption");
        setResizable(false);

        jPanel1.setBorder(BorderFactory.createTitledBorder("Decryption Menu"));

        jLabel1.setText("Encrypted File Name");
        
        jLabel5.setText("Signature File Name");

        jLabel2.setText("Sender Public Key");

        jLabel3.setText("Receiver Public Key");

        jLabel4.setText("Decrypted File Name");
        
        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1)
                    .addComponent(jLabel5)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4))
                .addGap(50, 50, 50)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(encryptFileName, javax.swing.GroupLayout.DEFAULT_SIZE, 193, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(signFileName)
                        .addComponent(publicKeyR)
                        .addComponent(publicKeyS)
                        .addComponent(decryptedFile))
                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    	.addGap(33, 33, 33)))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(encryptFileName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel5)
                        .addComponent(signFileName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
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
                    .addComponent(decryptedFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(27, 27, 27)))
                
                
        );

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        btnUploadEncrypt.setText("Upload Encrypted File");
        btnUploadEncrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnUploadEncryptActionPerformed(evt);
            }
        });
        btnUploadSign.setText("Upload Signature File");
        btnUploadSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnUploadSignActionPerformed(evt);
            }
        });

        btnDecrypt.setText("Decrypt");
        btnDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecryptActionPerformed(evt);
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
                    .addComponent(btnUploadEncrypt, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnUploadSign, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnDecrypt, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnReset, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(btnUploadEncrypt)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnUploadSign)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnDecrypt)
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
    	  	RSAPublicKey publicKey = readPublicKey("publicReceiver.rsa");
    		publicKeyR.setText(publicKey.toString());
    		publicKey = readPublicKey("publicSender.rsa");
    		publicKeyS.setText(publicKey.toString());
    	}catch(Exception e){
            JOptionPane.showMessageDialog(null,"KEYS NOT FOUND!!!GENERATE KEYS!!! ");
    		e.printStackTrace();
    	}
    }
    private void btnUploadSignActionPerformed(java.awt.event.ActionEvent evt) {
        filechooser f= new filechooser();
        String st=f.signfileName();
        signFileName.setText(st);
        try{
        	RSAPublicKey publicKey = (RSAPublicKey) readPublicKey("publicReceiver.rsa");
    		publicKeyR.setText(publicKey.toString());
    		publicKey = (RSAPublicKey) readPublicKey("publicSender.rsa");
    		publicKeyS.setText(publicKey.toString());
    	}catch(Exception e){
            JOptionPane.showMessageDialog(null,"KEYS NOT FOUND!!!GENERATE KEYS!!! ");
    		e.printStackTrace();
    	}
    }

    private void btnDecryptActionPerformed(java.awt.event.ActionEvent evt) {
    	try{
    		String encryptFile = encryptFileName.getText();
    		String signFile = signFileName.getText();
    		
    		FileInputStream cipherfile = new FileInputStream(encryptFile);
            byte[] cipherText = new byte[cipherfile.available()];
            cipherfile.read(cipherText);
            cipherfile.close();
    		

        	RSAPublicKey rsapub = (RSAPublicKey) readPublicKey("publicSender.rsa");
		    BigInteger E = rsapub.getPublicExponent();
		    BigInteger N = rsapub.getModulus();
		    
		    if(Verify(E,N,signFile)){
            	RSAPrivateKey privateKey = readPrivateKey("privateReceiver.rsa");
	        	//byte[] plainText = decrypt(cipherText, privateKey,stripExtension(signFile));
	        	decrypt(cipherText, privateKey,stripExtension(signFile));
	        	/*FileOutputStream fos = new FileOutputStream(stripExtension(signFile));
	            fos.write(plainText);
	            fos.close();*/
	        	decryptedFile.setText(stripExtension(signFile));
	      		JOptionPane.showMessageDialog(null,"Decrypted Successfully!!! ");
		    }
		    else{
		    	JOptionPane.showMessageDialog(null,"Decryption Unsuccessful!!!File not verified!!! ");
		    }
		
    	}catch(Exception e){
    		JOptionPane.showMessageDialog(null,"Decryption Unsuccessful!!! ");
    		e.printStackTrace();
    	}		    
    }
    
    
    /**
       * Decrypt text using private key.
       * 
       * @param text
       *          :encrypted text
       * @param key
       *          :The private key
       * @return plain text
       * @throws java.lang.Exception
    */

      public static void decrypt(byte[] text, PrivateKey key, String decryptedFile) {
    	  
    	//byte[] decryptedText = new byte[text.length];
    	byte[] temp =  new byte[LIMIT];
    	byte[] temp1 = new byte[LIMIT];
    	long i = 0,k = 0;
        try {
          final Cipher cipher = Cipher.getInstance(ALGORITHM);
          cipher.init(Cipher.DECRYPT_MODE, key);
          if(text.length <= LIMIT){
        	  temp1 = cipher.doFinal(text);
         }
          else{
              while(i != text.length){
            	  for(int j = 0 ; j < LIMIT ; j++,i++){
        			  temp[j]=text[(int) i];
            	  }        		 
            	  	System.out.println("temp "+ k +" "+temp1.length);
        		  	temp1 = cipher.doFinal(temp);
        		  
                	FileOutputStream plainfile = new FileOutputStream(k +".decrypt");
                	ObjectOutputStream plain =  new ObjectOutputStream(plainfile);
  	                plain.write(temp1);
  	                plain.close();
  	                k++;
  	                System.out.println("temp "+ k +" "+temp1.length);
                  }
		            
                }
              int fileNo=0;
              while(fileNo < k){
	              FileInputStream plainfile = new FileInputStream(fileNo +".decrypt");
	              byte[] cipherText = new byte[plainfile.available()];
	              plainfile.read(cipherText);
	              plainfile.close();
	              /*File file = new File(fileNo +".decrypt");
	              file.delete();*/
	              FileOutputStream signed = new FileOutputStream(decryptedFile);
	              signed.write(cipherText);
	              signed.close();
	              fileNo++;
    
        		/*  System.out.println(BitSet.valueOf(text).cardinality()+" "+BitSet.valueOf(temp1).cardinality());
      
        		  if(i <= LIMIT)
        	      		System.arraycopy(temp1, 0, decryptedText, 0, temp1.length);
        	      else
        	      		System.arraycopy(temp1, 0, decryptedText, decryptedText.length, temp1.length);
        		  temp=new byte[LIMIT];
        		  temp1=new byte[BitSet.valueOf(text).cardinality()];*/
            	}
     
        } catch (Exception ex) {
          ex.printStackTrace();
        }

        //return decryptedText;
     
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
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(UIDecryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(UIDecryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(UIDecryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(UIDecryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new UIDecryption().setVisible(true);
            }
        });
    }

    public  static boolean Verify(BigInteger E, BigInteger N, String file){
        
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
            	JOptionPane.showMessageDialog(null,"File: " + file + "not found\n"+"Decryption Unsuccessful!!! ");
                return false;
            }
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
    private JButton btnUploadEncrypt;
    private JButton btnUploadSign;
    public JButton btnDecrypt;
    public JButton btnReset;

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

    // End of variables declaration//GEN-END:variables
}