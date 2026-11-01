
API_KEYWORDS = [
    "/api", "api/", "graphql", "/v1/", "/v2/", "/v3/",
    "rest", "ajax", ".json", ".action", ".do"
]

API_PATTERNS = [
    r"/api/[a-zA-Z0-9/_-]+",
    r"/v[0-9]/[a-zA-Z0-9/_-]+",
    r"fetch\(\s*['\"](.*?)['\"]",
    r"axios\.[a-z]+\(\s*['\"](.*?)['\"]"
]

WEBSOCKET_PATTERNS = [
    r'["\'`](wss?://[a-zA-Z0-9._:/?=&%-]+)["\'`]',
    r'new\s+WebSocket\(\s*["\'`]([^"\'`]+)["\'`]',
    r'["\'`]([^"\'`]*\/(?:socket\.io|websocket|ws|wss)[^"\'`]*)["\'`]',
    r'io\(\s*["\'`]([^"\'`]+)["\'`]',
]

SENSITIVE_PATH_PATTERNS = {
    "admin_panel": [
        r'["\'`](/(?:admin|administrator|cpanel|wp-admin|phpmyadmin)(?:/index\.(?:php|html)?)?(?:/login)?)["\'`]',
        r'["\'`](/(?:backend|dashboard)(?:/login)?(?:/auth)?)["\'`]',
    ],
    "sensitive_files": [
        r'["\'`](/\.env(?:\.[a-z]+)?)["\'`]',
        r'["\'`](/\.git/(?:config|HEAD|index))["\'`]',
        r'["\'`](/\.htaccess|/\.htpasswd)["\'`]',
        r'["\'`](/\.aws/credentials)["\'`]',
        r'["\'`](/\.ssh/(?:id_rsa|id_ed25519|authorized_keys))["\'`]',
    ],
    "backup_files": [
        r'["\'`](/[a-zA-Z0-9/_-]+\.(?:bak|old|backup|sql|tar\.gz|zip|7z))["\'`]',
    ],
    "debug_internal": [
        r'["\'`](/(?:phpinfo|server-status|server-info|_debugbar|elmah)(?:\.|/|$))["\'`]',
    ],
    "api_docs": [
        r'["\'`](/(?:swagger-ui|swagger\.json|api-docs?|graphiql|graphql/playground|redoc)(?:/|$))["\'`]',
    ],
    "config_paths": [
        r'["\'`](/(?:config|settings|webpack\.config)(?:\.json|\.js|\.yml|\.yaml)?(?:/|$))["\'`]',
    ],
    "test_environments": [
        r'["\'`](https?://(?:staging|dev|sandbox|test)[a-zA-Z0-9._-]*\.[a-z]{2,})["\'`]',
    ],
    "secrets_in_code": [
        r'["\'`]((?:AKIA|ASIA)[A-Z0-9]{16})["\'`]',
        r'["\'`](AIza[0-9A-Za-z_-]{35})["\'`]',
        r'["\'`]((?:ghp|gho|ghu|ghs|ghr|glpat)[A-Za-z0-9_]{20,})["\'`]',
        r'["\'`](xox[abopr]-[0-9a-zA-Z-]{10,})["\'`]',
        r'["\'`]((?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{20,})["\'`]',
        r'["\'`](eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})["\'`]',
        r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)',
        r'["\'`]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\'`]',
    ]
}

CATEGORY_SEVERITY = {
    "secrets_in_code":   "CRITICAL",
    "sensitive_files":   "HIGH",
    "admin_panel":       "HIGH",
    "debug_internal":    "HIGH",
    "backup_files":      "MEDIUM",
    "config_paths":      "MEDIUM",
    "api_docs":          "LOW",
    "test_environments": "LOW",
}

SECRET_VALUE_BLOCKLIST = {
    "password", "passwd", "pwd", "secret", "token", "key", "apikey", "api_key",
    "admin", "administrator", "root", "user", "test", "testing", "demo",
    "changeme", "changeit", "placeholder", "example", "sample", "dummy",
    "xxx", "xxxx", "todo", "fixme", "temp", "temporary", "default",
    "123456", "12345678", "123456789", "1234567890", "password123",
    "letmein", "welcome", "qwerty", "abc123", "iloveyou",
    "true", "false", "yes", "no", "on", "off", "enabled", "disabled",
    "get", "post", "put", "delete", "patch", "options", "head",
    "null", "undefined", "none", "empty", "invalid", "unknown",
    "success", "error", "fail", "failed", "pending", "active", "inactive",
}

CONSTANT_CONTEXT_PATTERNS = [
    r'^\s*(?:export\s+)?(?:const|let|var|static|final)\s+[A-Z_]{3,}\s*=',  # CONSTANT = "value"
    r'^\s*[A-Z_]{3,}:\s*["\']',                                             # KEY: "value"
    r'^\s*case\s+["\']',                                                    # case "value":
    r'^\s*enum\s+',                                                          # enum declarations
    r'type\s+\w+\s*=\s*["\']',                                              # TypeScript types
    r'(?:action|mutation|getter)\s*:\s*["\']',                              # Vuex/Redux
    r'dispatch\(\s*["\']',                                                  # Redux dispatch
    r'commit\(\s*["\']',                                                    # Vuex commit
]

FAKE_LOCALHOST_PATTERNS = [
    r'https?://localhost',
    r'https?://127\.0\.0\.1',
    r'https?://0\.0\.0\.0',
    r'https?://\[::1\]',
]
HTTP_STATUS_SEVERITY = {
    200: "HIGH",
    201: "HIGH",
    204: "HIGH",
    301: "INFO",
    302: "INFO",
    307: "INFO",
    308: "INFO",
    401: "MEDIUM",
    403: "MEDIUM",
    404: "INFO",
    405: "MEDIUM",
    500: "MEDIUM",
    503: "MEDIUM",
}