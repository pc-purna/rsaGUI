
import java.io.FileOutputStream;
import javax.swing.*;
import java.security.*;


@SuppressWarnings("serial")
public class UI extends javax.swing.JFrame {

    public UI() {
        initComponents();
        setLocationRelativeTo(null);
                 }

    private void initComponents() {

        jMenuItem1 = new javax.swing.JMenuItem();
        btnEncrypt = new javax.swing.JButton();
        btnDecrypt = new javax.swing.JButton();
        btnGenerate = new javax.swing.JButton();
        filler1 = new javax.swing.Box.Filler(new java.awt.Dimension(0, 0), new java.awt.Dimension(0, 0), new java.awt.Dimension(32767, 0));

        jMenuItem1.setText("jMenuItem1");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Homepage");
        setResizable(false);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowOpened(java.awt.event.WindowEvent evt) {
                formWindowOpened(evt);
            }
        });

    
        btnEncrypt.setText("Encrypt");
        btnEncrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEncryptActionPerformed(evt);
            }
        });

        btnDecrypt.setText("Decrypt");
        btnDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecryptActionPerformed(evt);
            }
        });

        btnGenerate.setText("Generate Keys");
        btnGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerateActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(89, 89, 89)
                        .addComponent(filler1, javax.swing.GroupLayout.PREFERRED_SIZE, 86, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(32, 32, 32)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(35, 35, 35)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(btnEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(btnDecrypt)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(btnGenerate)))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(29, 29, 29)))))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnEncrypt)
                    .addComponent(btnDecrypt)
                    .addComponent(btnGenerate))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(filler1, javax.swing.GroupLayout.PREFERRED_SIZE, 11, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(20, 20, 20))
        );

        pack();
    }

    private void btnDecryptActionPerformed(java.awt.event.ActionEvent evt) {
             UIDecryption frm=new UIDecryption();
             frm.setVisible(true);
    }

     private void btnGenerateActionPerformed(java.awt.event.ActionEvent evt) {
        generateKey(PUBLIC_KEY_FILE_R,PRIVATE_KEY_FILE_R);
        generateKey(PUBLIC_KEY_FILE_S,PRIVATE_KEY_FILE_S);
        JOptionPane.showMessageDialog(null,"The keys are generated successfully!!!");           
    }
    private void formWindowOpened(java.awt.event.WindowEvent evt) {
   
    }
  
    private void btnEncryptActionPerformed(java.awt.event.ActionEvent evt) {
          UIEncryption frm=new UIEncryption();
             frm.setVisible(true);
             
    }
    public static void main(String args[]) {
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Metal".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(UI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new UI().setVisible(true);
            }
        });
    }
    

  /**
   * Generate key which contains a pair of private and public key using 1024
   * bytes. Store the set of keys in Prvate.key and Public.key files.
   * 
   * @throws NoSuchAlgorithmException
   * @throws IOException
   * @throws FileNotFoundException
   */
  public static void generateKey(String PUBLIC_KEY_FILE,String PRIVATE_KEY_FILE) {
    try {
      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
      keyGen.initialize(2048);
      final KeyPair key = keyGen.generateKeyPair();
      
      byte[] publicKeyBytes = key.getPublic().getEncoded();
      FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE);
      fos.write(publicKeyBytes);
      fos.close();
     
      byte[] privateKeyBytes = key.getPrivate().getEncoded();
      fos = new FileOutputStream(PRIVATE_KEY_FILE);
      fos.write(privateKeyBytes);
      fos.close();
 
      
    } catch (Exception e) {
      e.printStackTrace();
    }
     
  }
	public static final String ALGORITHM = "RSA";
	public static final String PRIVATE_KEY_FILE_R = "privateR.rsa";
	public static final String PUBLIC_KEY_FILE_R = "publicR.rsa";
	public static final String PRIVATE_KEY_FILE_S = "privateS.rsa";
	public static final String PUBLIC_KEY_FILE_S = "publicS.rsa";
	private javax.swing.JButton btnDecrypt;
	private javax.swing.JButton btnEncrypt;
	private javax.swing.JButton btnGenerate;
	private javax.swing.Box.Filler filler1;
	private javax.swing.JMenuItem jMenuItem1;
	public javax.swing.JPasswordField txtPassword;
	public javax.swing.JTextField txtUserName;

}