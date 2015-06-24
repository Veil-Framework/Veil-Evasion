;writes a string and a newline to the logfile
macro writeWithNewLine char_sequence, char_buffer, error_exit{
    char_sequence char_buffer
	mov eax,1
}

;write a string to the logfile
macro writeLog apitable, content{
	mov eax,1
}

;delete old log file and create a new one
macro initLogFile apitable{
	 mov eax,1
}

;write a newline into logfile
macro writeNewLineToLog apitable{
	mov eax,1
}

;write a register value into logile
macro writeRegisterToLog apitable, value{
	mov eax,1
}