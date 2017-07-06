package burp.gui;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public abstract class ADocumentListener implements DocumentListener {

    /**
     * Implements all kinds of changes in document
     */
    abstract void update(DocumentEvent e);

    @Override
    public void insertUpdate(DocumentEvent e) {
        update(e);
    }
    @Override
    public void removeUpdate(DocumentEvent e) {
        update(e);
    }
    @Override
    public void changedUpdate(DocumentEvent e) {
        update(e);
    }
}