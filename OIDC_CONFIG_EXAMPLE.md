# OIDC Configuration Examples

Cloudreve stores settings as string values. The `oidc_providers` setting expects a JSON array of provider entries. Below are minimal examples in YAML, JSON, and environment-variable formats.

## YAML

```yaml
oidc_providers:
  - name: "google"
    issuer_url: "https://accounts.google.com"
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    redirect_uri: "https://cloudreve.example.com/api/v3/auth/oidc/google/callback"
    scopes:
      - "openid"
      - "email"
      - "profile"
    allow_email_link: true
    auto_create_user: true
```

## JSON

```json
{
  "oidc_providers": [
    {
      "name": "google",
      "issuer_url": "https://accounts.google.com",
      "client_id": "your-client-id",
      "client_secret": "your-client-secret",
      "redirect_uri": "https://cloudreve.example.com/api/v3/auth/oidc/google/callback",
      "scopes": ["openid", "email", "profile"],
      "allow_email_link": true,
      "auto_create_user": true
    }
  ]
}
```

## Environment Variable

```bash
export CR_SETTING_oidc_providers='[{"name":"google","issuer_url":"https://accounts.google.com","client_id":"your-client-id","client_secret":"your-client-secret","redirect_uri":"https://cloudreve.example.com/api/v3/auth/oidc/google/callback","scopes":["openid","email","profile"],"allow_email_link":true,"auto_create_user":true}]'
```
