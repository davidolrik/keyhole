package storage_test

import (
	"errors"
	"testing"

	"go.olrik.dev/keyhole/internal/storage"
)

func TestFileStore_WriteRead(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	data := []byte("encrypted-data")
	if err := store.Write("alice", "account/github", data); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := store.Read("alice", "account/github")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("Read = %q, want %q", got, data)
	}
}

func TestFileStore_ReadNotFound(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	_, err := store.Read("alice", "nonexistent/secret")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Read nonexistent = %v, want ErrNotFound", err)
	}
}

func TestFileStore_List(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	secrets := []string{
		"account/github",
		"account/twitter",
		"database/prod",
	}
	for _, s := range secrets {
		if err := store.Write("alice", s, []byte("data")); err != nil {
			t.Fatalf("Write %q: %v", s, err)
		}
	}

	t.Run("list with prefix", func(t *testing.T) {
		got, err := store.List("alice", "account")
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("List account = %v (len %d), want 2 items", got, len(got))
		}
		for _, p := range got {
			if p != "account/github" && p != "account/twitter" {
				t.Errorf("unexpected path %q", p)
			}
		}
	})

	t.Run("list all", func(t *testing.T) {
		got, err := store.List("alice", "")
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 3 {
			t.Errorf("List all = %v (len %d), want 3 items", got, len(got))
		}
	})

	t.Run("list with no matches", func(t *testing.T) {
		got, err := store.List("alice", "nonexistent")
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("List nonexistent = %v, want empty", got)
		}
	})
}

func TestFileStore_WriteOverwrite(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.Write("alice", "secret", []byte("original")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := store.Write("alice", "secret", []byte("updated")); err != nil {
		t.Fatalf("Write overwrite: %v", err)
	}

	got, err := store.Read("alice", "secret")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "updated" {
		t.Errorf("Read after overwrite = %q, want %q", got, "updated")
	}
}

func TestFileStore_IsolatesByUser(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.Write("alice", "secret", []byte("alice-data")); err != nil {
		t.Fatalf("Write alice: %v", err)
	}
	if err := store.Write("bob", "secret", []byte("bob-data")); err != nil {
		t.Fatalf("Write bob: %v", err)
	}

	aliceData, err := store.Read("alice", "secret")
	if err != nil {
		t.Fatalf("Read alice: %v", err)
	}
	if string(aliceData) != "alice-data" {
		t.Errorf("alice data = %q, want alice-data", aliceData)
	}

	bobData, err := store.Read("bob", "secret")
	if err != nil {
		t.Fatalf("Read bob: %v", err)
	}
	if string(bobData) != "bob-data" {
		t.Errorf("bob data = %q, want bob-data", bobData)
	}
}

func TestFileStore_ListEmpty(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	got, err := store.List("alice", "")
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List empty user = %v, want empty", got)
	}
}
