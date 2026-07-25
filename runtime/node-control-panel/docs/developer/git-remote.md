# Git Remote Setup

Repo path on this workspace:

```bash
cd /Users/devpup/Desktop/synergy-testnet/tools/testnet-control-panel
```

Current GitHub remote:

```text
https://github.com/synergy-network-hq/testnet-control-panel.git
```

## Preferred: SSH Remote

```bash
git remote set-url origin git@github.com:synergy-network-hq/testnet-control-panel.git
git fetch origin
git pull origin main
```

## HTTPS Remote

```bash
git remote set-url origin https://github.com/synergy-network-hq/testnet-control-panel.git
git fetch origin
git pull origin main
```

If GitHub prompts repeatedly over HTTPS, configure a credential helper or switch to SSH.
# Enter your GitHub username and use the token as password when prompted
```

### Option 3: Check Available Branches First

```bash
cd /home/devpup/Desktop/testnet-control-panel
# Try to see what branches exist (may work if repo is public)
git ls-remote --heads origin

# Then pull the appropriate branch
git pull origin <branch-name> --allow-unrelated-histories
```

## If You Have Local Changes

Before pulling, you may want to:

1. **Commit your local changes:**
```bash
git add .
git commit -m "Local changes before pulling from remote"
```

2. **Or stash them:**
```bash
git stash
git pull origin main
git stash pop  # Reapply your changes after pulling
```

## Verify Remote

```bash
git remote -v
```

Should show:
```
origin  https://github.com/synergy-network-hq/testnet-control-panel.git (fetch)
origin  https://github.com/synergy-network-hq/testnet-control-panel.git (push)
```
