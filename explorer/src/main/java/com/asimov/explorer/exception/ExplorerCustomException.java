package com.asimov.explorer.exception;

public class ExplorerCustomException extends Exception {
    private static final long serialVersionUID = 1L;
    
    public ExplorerCustomException(String errorMessage, Throwable err) {
        super(errorMessage, err);
    }

	public ExplorerCustomException(String string) {
        super(string);
	}
    
}