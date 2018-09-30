test: 427_totpv2.0.c
	gcc -o totp 427_totpv2.0.c -lcrypto -lm
	./totp test
run: 427_totpv2.0.c
	gcc -o totp 427_totpv2.0.c -lcrypto -lm
	./totp run
clean:
	rm totp
