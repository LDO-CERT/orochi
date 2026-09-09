/*
    Curated Secrets & Credentials YARA Ruleset for Orochi Memory Triage
    Detects API keys, tokens, private keys, database connection strings, and credentials.
*/

rule Secret_AWS_Access_Key {
    meta:
        category = "aws"
        description = "AWS Access Key ID"
    strings:
        $key = /AKIA[0-9A-Z]{16}/
    condition:
        $key
}

rule Secret_Private_Key_PEM {
    meta:
        category = "private_key"
        description = "PEM Private Key Header"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $dsa = "-----BEGIN DSA PRIVATE KEY-----"
        $generic = "-----BEGIN PRIVATE KEY-----"
        $enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    condition:
        any of them
}

rule Secret_JWT_Token {
    meta:
        category = "jwt"
        description = "JSON Web Token (JWT)"
    strings:
        $jwt = /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+/
    condition:
        $jwt
}

rule Secret_GitHub_Token {
    meta:
        category = "api_key"
        description = "GitHub Personal Access or OAuth Token"
    strings:
        $ghp = /gh[pousr]_[0-9a-zA-Z]{36}/
    condition:
        $ghp
}

rule Secret_Slack_Token {
    meta:
        category = "api_key"
        description = "Slack API Token"
    strings:
        $slack = /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}/
    condition:
        $slack
}

rule Secret_OpenAI_Key {
    meta:
        category = "api_key"
        description = "OpenAI API Key"
    strings:
        $sk1 = /sk-[a-zA-Z0-9]{32,50}/
        $sk2 = /sk-proj-[a-zA-Z0-9_-]{40,60}/
    condition:
        any of them
}

rule Secret_Database_Connection_URI {
    meta:
        category = "db_uri"
        description = "Database Connection String with Credentials"
    strings:
        $postgres = /postgres:\/\/[a-zA-Z0-9_.-]+:[^@\s\r\n]+@[a-zA-Z0-9_.-]+/
        $mysql = /mysql:\/\/[a-zA-Z0-9_.-]+:[^@\s\r\n]+@[a-zA-Z0-9_.-]+/
        $mongodb = /mongodb:\/\/[a-zA-Z0-9_.-]+:[^@\s\r\n]+@[a-zA-Z0-9_.-]+/
        $redis = /redis:\/\/:[^@\s\r\n]+@[a-zA-Z0-9_.-]+/
    condition:
        any of them
}

rule Secret_Generic_Credentials {
    meta:
        category = "password"
        description = "Hardcoded Password or Credential Assignment"
    strings:
        $p1 = /(password|passwd|api_key|secret_key)[=:\s]{1,4}["\x27]?[A-Za-z0-9@#$%^&*()_+=!~-]{8,64}["\x27]?/ ascii wide nocase
    condition:
        $p1
}
