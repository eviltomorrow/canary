package znet

import "testing"

func TestGetFreePort(t *testing.T) {
	port, err := GetFreePort()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("port: %v\r\n", port)
}
