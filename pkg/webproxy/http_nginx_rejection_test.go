package webproxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPNginxBufferedAdmissionRejection(t *testing.T) {
	if os.Getenv("TELEGO_TEST_NGINX_UPLOAD_REJECTION") != "1" {
		t.Skip("run make test-web-nginx for the isolated Nginx integration gate")
	}
	app := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
		config.Limits.MaxPendingPerSession = 200 * 1024
	}, nil)
	created := createTestSession(t, app.manager, app.profiles[0])
	address := unusedTCPAddress(t)
	directory := t.TempDir()
	config := fmt.Sprintf(`worker_processes 1;
pid %s/nginx.pid;
error_log %s/errors.log warn;
events { worker_connections 64; }
http {
 access_log %s/access.log combined;
 client_body_temp_path %s/client;
 proxy_temp_path %s/proxy;
 fastcgi_temp_path %s/fastcgi;
 uwsgi_temp_path %s/uwsgi;
 scgi_temp_path %s/scgi;
 server {
  listen %s;
  client_max_body_size 16m;
  location = /ready { return 204; }
  location / {
   proxy_pass http://%s;
   proxy_http_version 1.1;
   proxy_set_header Host proxy.example.com;
   proxy_set_header Connection "";
   proxy_request_buffering on;
   proxy_buffering off;
   proxy_next_upstream off;
   proxy_read_timeout 40s;
   proxy_send_timeout 40s;
  }
 }
}
`, directory, directory, directory, directory, directory, directory, directory, directory, address, app.address)
	path := filepath.Join(directory, "nginx.conf")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "nginx", "-c", path, "-g", "daemon off;")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	client := &http.Client{Timeout: 10 * time.Second}
	eventually(t, 3*time.Second, func() bool {
		response, err := client.Get("http://" + address + "/ready")
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		return response.StatusCode == 204
	})
	body := bytes.Repeat([]byte{0xff}, maxCarrierBatchBytes)
	statuses := make(map[int]int)
	for range 12 {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+address+"/api/v1/up", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+created.Token)
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("X-Up-Seq", "1")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		statuses[response.StatusCode]++
	}
	waitRejectedUploadPermits(t, created.Session, 0, 0)
	log, err := os.ReadFile(filepath.Join(directory, "errors.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client_status_counts=%v backend_admission_backpressure=%d nginx_sendfile_failures=%d nginx_upstream_premature=%d", statuses,
		app.manager.backpressure[carrierOperationUplink].Load(), strings.Count(string(log), "sendfile() failed"), strings.Count(string(log), "upstream prematurely closed"))
	if statuses[http.StatusServiceUnavailable] != 12 {
		t.Fatalf("authenticated pre-body admission rejection lost retryable 503: client_status_counts=%v", statuses)
	}
}
