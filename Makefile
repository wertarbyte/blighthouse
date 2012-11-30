blighthouse: blighthouse.c
	${CC} $< -lpcap -o $@

clean:
	@rm blighthouse
