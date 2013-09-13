package com.muddlemail.MuddleClient.gui;

import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.MenuItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.events.MouseAdapter;
import org.eclipse.swt.events.MouseEvent;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;

import com.muddlemail.MuddleClient.http.FailedPostException;
import com.muddlemail.MuddleClient.http.JsonResponse;
import com.muddlemail.MuddleClient.http.PostJson;
import com.muddlemail.MuddleClient.models.MailMessage;

public class MainWindow {
///////////////////////////////////////////////////////////////////////////////
// Class Variables ////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
	protected Shell shell;
	private Text textEmailBody;
	private Text textHttpReturn;

	/**
	 * @wbp.parser.entryPoint
	 */
	public void open() {
		Display display = Display.getDefault();
		createContents();
		shell.open();
		shell.layout();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}

	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shell = new Shell();
		shell.setSize(450, 300);
		shell.setText("SWT Application");
		shell.setLayout(null);
		
		Menu menu = new Menu(shell, SWT.BAR);
		shell.setMenuBar(menu);
		
		MenuItem mntmFileSubmenu = new MenuItem(menu, SWT.CASCADE);
		mntmFileSubmenu.setText("File");
		
		Menu menu_1 = new Menu(mntmFileSubmenu);
		mntmFileSubmenu.setMenu(menu_1);
		
		MenuItem mntmFileQuit = new MenuItem(menu_1, SWT.NONE);
		mntmFileQuit.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				System.out.println("MenuBar->File->Quit Selected.");
			}
		});
		mntmFileQuit.setText("Quit");
		
		textEmailBody = new Text(shell, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		textEmailBody.setBounds(10, 10, 428, 109);
		
		textHttpReturn = new Text(shell, SWT.BORDER | SWT.WRAP | SWT.H_SCROLL | SWT.CANCEL | SWT.MULTI);
		textHttpReturn.setEnabled(false);
		textHttpReturn.setEditable(false);
		textHttpReturn.setBounds(10, 125, 428, 68);
		
		Button btnSend = new Button(shell, SWT.NONE);
		btnSend.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseUp(MouseEvent event) {
				System.out.println("Send-button clicked.");
				MailMessage mailMsg = new MailMessage(
						textEmailBody.getText(), 
						"This is the IV", 
						"RSA Encrypted AES-Password");
				PostJson post = new PostJson("http://localhost:3000/api/json/mail/abcdefg", mailMsg);
				try {
					JsonResponse resp = post.executePost();
					textHttpReturn.setText(
							resp.getHttpReturnCode() + "\n" + 
							resp.getJson());
				} catch (FailedPostException e) {
					textHttpReturn.setText("Failed to post mail-message.");
					e.printStackTrace();
				}
			}
		});
		btnSend.setBounds(10, 209, 91, 29);
		btnSend.setText("Send");
		
		Button btnClear = new Button(shell, SWT.NONE);
		btnClear.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseUp(MouseEvent e) {
				System.out.println("Clear-button clicked.");
				textEmailBody.setText("");
				textHttpReturn.setText("");
			}
		});
		btnClear.setBounds(347, 209, 91, 29);
		btnClear.setText("Clear");
		
		Button btnNewButton = new Button(shell, SWT.NONE);
		btnNewButton.setBounds(170, 209, 91, 29);
		btnNewButton.setText("New Button");

	}
}
