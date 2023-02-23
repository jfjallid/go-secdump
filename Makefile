all:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o go-secdump
	GOOS=windows GOARCH=386 go build -ldflags "-s -w" -o go-secdump.exe .

clean:
	rm -f go-secdump
	rm -f go-secdump.exe
