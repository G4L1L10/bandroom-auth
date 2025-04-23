# Band Room Authentication Commands

## Start the authentication service

go run cmd/main.go

## Register a New User

curl -X POST http://localhost:8081/auth/register \
 -H "Content-Type: application/json" \
 -d '{
"email": "user1@email.com",
"password": "P4ssword!"
}' | jq

### Expected Response

{
"message": "User registered successfully",
"user_id": "generated-uuid-here"
}

## Login & Get Tokens (Access + Refresh)

curl -X POST http://localhost:8081/auth/login \
 -H "Content-Type: application/json" \
 -d '{
"email": "user1@email.com",
"password": "P4ssword!"
}' \
 -c cookies.txt | jq

### Expected Response

{
"message": "Login successful",
"access_token": "your-jwt-access-token",
"refresh_token": "your-jwt-refresh-token"
}

## Validate an Access Token

curl -X GET http://localhost:8081/auth/validate \
 -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" | jq

### Expected Response

{
"message": "Token is valid",
"user_id": "your-user-id"
}

## Refresh Access Token

curl -X POST http://localhost:8081/auth/refresh \
 -b cookies.txt | jq

### Expected Response

{
"access_token": "new_access_token_here"
}

## Logout (Invalidate Refresh Token)

curl -X POST http://localhost:8080/auth/logout \
 -b cookies.txt | jq

### Expected Response

{
"message": "Logout successful"
}

\c bandroom_admin;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
email TEXT UNIQUE NOT NULL,
password_hash TEXT NOT NULL,
role TEXT NOT NULL DEFAULT 'user',
refresh_token TEXT,
last_password_change TIMESTAMPTZ NOT NULL DEFAULT NOW(),
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
