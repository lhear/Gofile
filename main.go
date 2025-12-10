package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	baseDir   string
	templates *template.Template
)

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>File Manager</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; color: #333; }
        h1, h2 { border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
        ul { list-style: none; padding: 0; }
        li { padding: 0.5rem 0; border-bottom: 1px solid #f0f0f0; display: flex; justify-content: space-between; align-items: center; }
        a { text-decoration: none; color: #007bff; }
        a:hover { text-decoration: underline; }
        .meta { color: #666; font-size: 0.9em; margin-right: 1rem; }
        button { background: #dc3545; color: white; border: none; padding: 0.3rem 0.6rem; border-radius: 4px; cursor: pointer; }
        button:hover { background: #c82333; }
        .upload-form { background: #f8f9fa; padding: 1rem; border-radius: 4px; margin-bottom: 2rem; }
    </style>
</head>
<body>
    <h1>File Manager</h1>

    <div class="upload-form">
        <h2>Upload File</h2>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit" style="margin-top: 10px;display: block">Upload</button>
        </form>
    </div>

    <h2>Files ({{.FileCount}})</h2>
    <ul>
        {{range .Files}}
            <li>
                <span>
                    <a href="/download/{{.Name}}">{{.Name}}</a>
                </span>
                <div>
                    <span class="meta">{{.Size}}</span>
                    <form action="/delete/{{.Name}}" method="post" onsubmit="return confirm('Are you sure you want to delete {{.Name}}?')" style="display:inline;">
                        <input type="hidden" name="_method" value="DELETE">
                        <button type="submit">Delete</button>
                    </form>
                </div>
            </li>
        {{else}}
            <li>No files found.</li>
        {{end}}
    </ul>
</body>
</html>`

type FileInfo struct {
	Name string
	Size string
}

type TemplateData struct {
	Files     []FileInfo
	FileCount int
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func init() {
	var err error
	templates, err = template.New("main").Parse(htmlTmpl)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}
}

func getSafePath(filename string) (string, bool) {
	if filename == "" || filename == "." || filename == ".." {
		return "", false
	}
	if strings.ContainsAny(filename, "/\\") {
		return "", false
	}
	fullPath := filepath.Join(baseDir, filename)
	cleanPath := filepath.Clean(fullPath)
	if !strings.HasPrefix(cleanPath, baseDir) {
		return "", false
	}
	return cleanPath, true
}

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, DELETE")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		origin := r.Header.Get("Origin")
		host := r.Header.Get("Host")
		if origin != "" && !strings.Contains(origin, host) {
			http.Error(w, "Forbidden: Cross-origin request denied", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		log.Printf("Error reading directory: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	files := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name: entry.Name(),
			Size: formatSize(info.Size()),
		})
	}

	if err := templates.Execute(w, TemplateData{Files: files, FileCount: len(files)}); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 500<<20) 
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		http.Error(w, "File too large or malformed request", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Invalid file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	path, ok := getSafePath(filepath.Base(header.Filename))
	if !ok {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(path); err == nil {
		http.Error(w, "File already exists", http.StatusConflict)
		return
	}

	dst, err := os.Create(path)
	if err != nil {
		log.Printf("Create file error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("Save file error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("Uploaded: %s", header.Filename)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/download/")
	path, ok := getSafePath(name)
	if !ok {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.Error(w, "File Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.PostFormValue("_method") != "DELETE" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/delete/")
	path, ok := getSafePath(name)
	if !ok {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File Not Found", http.StatusNotFound)
			return
		}
		log.Printf("Delete error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("Deleted: %s", name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <directory> <port>\n", os.Args[0])
		os.Exit(1)
	}

	var err error
	baseDir, err = filepath.Abs(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid directory: %v", err)
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	port, err := strconv.Atoi(os.Args[2])
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("Invalid port: %s", os.Args[2])
	}

	mux := http.NewServeMux()
	mux.Handle("/", securityMiddleware(http.HandlerFunc(listHandler)))
	mux.Handle("/upload", securityMiddleware(http.HandlerFunc(uploadHandler)))
	mux.Handle("/download/", securityMiddleware(http.HandlerFunc(downloadHandler)))
	mux.Handle("/delete/", securityMiddleware(http.HandlerFunc(deleteHandler)))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("Server started on http://127.0.0.1:%d serving %s", port, baseDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
