package x.mvmn.dkimchecker;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import org.apache.james.jdkim.DKIMVerifier;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.impl.Message;

public class DKIMChecker {

	private static volatile int threadCount = 8;

	public static void main(String[] args) {
		new DKIMChecker();
		if (args.length > 0) {
			try {
				threadCount = Integer.parseInt(args[0]);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static interface ScanCallback {
		public void call(String scanResultLine);
	}

	private static final String EMPTY_SHA256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
	protected final DKIMVerifier verifier = new DKIMVerifier();
	protected final JTextArea txaLog = new JTextArea();

	public DKIMChecker() {
		final JFrame window = new JFrame("DKIMChecker by Mykola Makhin.");
		window.getContentPane().setLayout(new BorderLayout());
		window.getContentPane().add(new JScrollPane(txaLog), BorderLayout.CENTER);
		final JButton btnScan = new JButton("Choose folder to scan recursively for .eml files and verify DKIMs...");
		window.getContentPane().add(btnScan, BorderLayout.SOUTH);
		window.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		btnScan.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser jfc = new JFileChooser();
				jfc.setDialogTitle("Choose folder to scan");
				jfc.setMultiSelectionEnabled(false);
				jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				if (JFileChooser.APPROVE_OPTION == jfc.showOpenDialog(window)) {
					btnScan.setEnabled(false);
					txaLog.append("Scanning folder " + jfc.getSelectedFile().getAbsolutePath() + "...\n");
					new Thread() {
						public void run() {
							try {
								ExecutorService exs = Executors.newFixedThreadPool(threadCount);
								verifyRecursively(exs, jfc.getSelectedFile(), new DKIMChecker.ScanCallback() {
									public void call(final String scanResultLine) {
										try {
											SwingUtilities.invokeLater(new Runnable() {
												public void run() {
													txaLog.append(scanResultLine + "\n");
												}
											});
										} catch (Throwable t) {
											t.printStackTrace();
										}
									}
								});
								exs.shutdown();
								exs.awaitTermination(1, TimeUnit.DAYS);
								SwingUtilities.invokeLater(new Runnable() {
									public void run() {
										JOptionPane.showMessageDialog(window, "Scan finished.");
									}
								});
							} catch (final Throwable t) {
								t.printStackTrace();
								SwingUtilities.invokeLater(new Runnable() {
									public void run() {
										JOptionPane.showMessageDialog(window, "Scan failed: " + t.getClass().getName() + " " + t.getMessage());
									}
								});
							} finally {
								SwingUtilities.invokeLater(new Runnable() {
									public void run() {
										btnScan.setEnabled(true);
										txaLog.append("Scan finished.\n");
									}
								});
							}
						}
					}.start();
				}
			}
		});
		window.pack();
		window.setVisible(true);
	}

	public void verifyRecursively(final ExecutorService exs, final File file, final ScanCallback callback) {
		if (file.isDirectory()) {
			for (File f : file.listFiles()) {
				verifyRecursively(exs, f, callback);
			}
		} else {
			if (file.getName().endsWith(".eml")) {
				exs.submit(new Runnable() {
					public void run() {
						Message message = null;
						try {
							FileInputStream fis = new FileInputStream(file);
							message = new Message(fis);
							List<SignatureRecord> sigs = verifier.verify(message, message.getBodyInputStream());
							message.dispose();
							fis.close();
							if (sigs != null && sigs.size() > 0) {
								callback.call("v Verified " + sigs.size() + " signature records: " + file.getAbsolutePath());
							} else {
								callback.call("? NON-Verified - 0 signature records: " + file.getAbsolutePath());
							}
						} catch (Throwable e) {
							String hasEmptyHash = "";
							try {
								for (String field : message.getFields()) {
									if (field.contains(EMPTY_SHA256)) {
										hasEmptyHash = "(has body hash for empty body)";
										break;
									}
								}
							} catch (Exception ex) {
								ex.printStackTrace();
								callback.call("Error: " + ex.getClass().getName() + " " + ex.getMessage());
							}
							callback.call("x Verification failed - " + hasEmptyHash + " " + e.getMessage() + ": " + file.getAbsolutePath() + ". "
									+ message.getFields("From"));
						}
					}
				});
			} else {
				callback.call("- Skipping " + file.getAbsolutePath());
			}
		}
	}
}
