# 📦 Release Notes — `getsploit` v2.0.2

## ✅ Python Compatibility
- Minimum supported Python version is now **3.10+**.

## 🔐 API Key Management
You can now provide your API key in several ways:

1. Save the key for the current user:
```bash
   getsploit --set-key YOUR-KEY
```

2. Alternatively, pass the key:

   * via the `--api-key` command-line option
   * or through the `VULNERS_API_KEY` environment variable

**Key resolution priority:**

1. If `--api-key` is provided, it takes precedence.
2. If not, the `VULNERS_API_KEY` environment variable is used.
3. If neither is set, the saved key from `--set-key` is used.

## 🔍 Query Behavior

* Search queries are now passed **as-is**, without modification.

### 🔎 Search in title only:

```bash
getsploit title:wordpress AND title:"4.7.0"
```

### 🔎 Search across all fields:

```bash
getsploit wordpress sql injection
```

⚠️ When searching in the local database, queries must be compatible with **FTS4** (Full-Text Search v4).

## 🏷 Available Search Fields

* `id`
* `title`
* `description`
* `sourceData`
* `published`
