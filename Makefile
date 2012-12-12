blighthouse: blighthouse.c network.c packet.c
	${CC} $+ -lpcap -o $@

clean:
	@rm blighthouse
