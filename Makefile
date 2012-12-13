blighthouse: blighthouse.c network.c packet.c
	${CC} --std=c99 -D_GNU_SOURCE $+ -lpcap -o $@

clean:
	@rm blighthouse
