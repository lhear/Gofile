# Gofile

**Gofile** is a lightweight, single-file HTTP file server written in **Golang**. It provides a simple web interface for browsing, uploading, and downloading files from a local directory. It's designed for **minimal overhead** and **easy deployment**.

## Key Features

* **Single-Binary:** Zero dependencies, cross-platform executable.
* **Web Access:** Manage files using any standard browser.

## Usage

### Build

```bash
go build -trimpath -ldflags "-s -w" -o gofile ./main.go
```

### Run

```bash
./gofile ./files/ 8080
```

