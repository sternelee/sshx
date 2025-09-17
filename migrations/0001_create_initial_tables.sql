-- Migration: create_initial_tables
-- Created at: 2025-09-17

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    encrypted_zeros BLOB NOT NULL,
    write_password_hash BLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create shells table
CREATE TABLE IF NOT EXISTS shells (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    x INTEGER NOT NULL,
    y INTEGER NOT NULL,
    rows INTEGER NOT NULL,
    cols INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- Create terminal_data table
CREATE TABLE IF NOT EXISTS terminal_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shell_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    data BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shell_id) REFERENCES shells(id) ON DELETE CASCADE
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    name TEXT NOT NULL,
    can_write BOOLEAN NOT NULL DEFAULT TRUE,
    cursor_x INTEGER,
    cursor_y INTEGER,
    focus_shell_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (focus_shell_id) REFERENCES shells(id) ON DELETE SET NULL
);

-- Create chat_messages table
CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_shells_session_id ON shells(session_id);
CREATE INDEX IF NOT EXISTS idx_terminal_data_shell_id ON terminal_data(shell_id);
CREATE INDEX IF NOT EXISTS idx_terminal_data_sequence ON terminal_data(sequence_number);
CREATE INDEX IF NOT EXISTS idx_users_session_id ON users(session_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
