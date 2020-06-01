package com.asimov.executor.exception;

public class ExecutorCustomException extends Exception {
    private static final long serialVersionUID = 1L;
    
    public ExecutorCustomException(String errorMessage, Throwable err) {
        super(errorMessage, err);
    }

	public ExecutorCustomException(String string) {
        super(string);
	}
    
}