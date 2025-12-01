#!/bin/bash
# Database initialization script
# This script contains several security issues for demonstration purposes

# Issue 1: Hardcoded credentials
ADMIN_PASSWORD="admin123"
APP_PASSWORD="appuser123"

# Issue 2: Creating user with superuser privileges
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Issue 3: Granting excessive privileges
    CREATE USER app_user WITH PASSWORD '$APP_PASSWORD' SUPERUSER;
    
    -- Issue 4: No password complexity requirements
    CREATE USER readonly_user WITH PASSWORD 'read123';
    
    -- Issue 5: Granting all privileges
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO app_user;
    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;
    
    -- Issue 6: Creating tables without proper constraints
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255),
        password VARCHAR(255),  -- Issue 7: Storing passwords in plain text
        email VARCHAR(255),
        role VARCHAR(50) DEFAULT 'admin'  -- Issue 8: Default role is admin
    );
    
    -- Issue 9: Inserting test data with weak passwords
    INSERT INTO users (username, password, email, role) VALUES
        ('admin', 'admin123', 'admin@example.com', 'admin'),
        ('test', 'test123', 'test@example.com', 'user');
    
    -- Issue 10: No audit logging enabled
EOSQL

# Issue 11: Echoing sensitive information
echo "Database initialized with password: $ADMIN_PASSWORD"
