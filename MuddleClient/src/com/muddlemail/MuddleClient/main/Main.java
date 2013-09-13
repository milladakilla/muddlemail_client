package com.muddlemail.MuddleClient.main;

import com.muddlemail.MuddleClient.gui.MainWindow;

public class Main {

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			MainWindow window = new MainWindow();
			window.open();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
