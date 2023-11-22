all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-secdump
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-secdump.exe .

clean:
	rm -f go-secdump
	rm -f go-secdump.exe
