package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type noticeEOF struct {
	io.Reader
	done chan struct{}
}

func (r noticeEOF) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if err == io.EOF {
		close(r.done)
	}
	return n, err
}

type blockedPromptOutput struct {
	entered chan struct{}
	release chan struct{}
}

func (w blockedPromptOutput) Write(b []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(b), nil
}

func TestTerminalSMSKeepsCodeReceivedWhilePrintingPrompt(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	eof := make(chan struct{})
	output := blockedPromptOutput{make(chan struct{}), make(chan struct{})}
	defer func() {
		select {
		case <-output.release:
		default:
			close(output.release)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan string, 1)
	prompt := &terminalCodeInput{}
	go func() {
		code, err := prompt.prompt(ctx, noticeEOF{input, eof}, output)
		if err != nil {
			code = "error: " + err.Error()
		}
		result <- code
	}()
	<-output.entered
	if _, err := writer.Write([]byte("123456\n")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	<-eof
	close(output.release)
	if code := <-result; code != "123456" {
		t.Fatalf("early SMS code lost: %s", code)
	}
}

func TestCancelledTerminalSMSDoesNotConsumeTheNextCode(t *testing.T) {
	prompt := &terminalCodeInput{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prompt.prompt(ctx, strings.NewReader("old input\n"), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled prompt = %v", err)
	}
	code, err := prompt.prompt(context.Background(), strings.NewReader("654321\n"), io.Discard)
	if err != nil || code != "654321" {
		t.Fatalf("next prompt = %q, %v", code, err)
	}
	if _, err := prompt.prompt(context.Background(), strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("closed input did not report EOF")
	}
}
