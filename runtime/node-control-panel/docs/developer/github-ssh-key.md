# Setting Up SSH Key for GitHub

## Step 1: Check for Existing SSH Keys

```bash
ls -la ~/.ssh/*.pub
```

If you see files like `id_rsa.pub`, `id_ed25519.pub`, etc., you may already have SSH keys.

## Step 2: Generate a New SSH Key

### Option A: Ed25519 (Recommended - more secure and faster)

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

When prompted:
- **File location**: Press Enter to accept default (`~/.ssh/id_ed25519`)
- **Passphrase**: Enter a secure passphrase (or press Enter for no passphrase, less secure)

### Option B: RSA (If Ed25519 is not supported)

```bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

## Step 3: Start the SSH Agent

```bash
eval "$(ssh-agent -s)"
```

Should output something like: `Agent pid 12345`

## Step 4: Add Your SSH Key to the SSH Agent

### For Ed25519:
```bash
ssh-add ~/.ssh/id_ed25519
```

### For RSA:
```bash
ssh-add ~/.ssh/id_rsa
```

If you set a passphrase, you'll be prompted to enter it.

## Step 5: Copy Your Public Key

```bash
cat ~/.ssh/id_ed25519.pub
```

Or for RSA:
```bash
cat ~/.ssh/id_rsa.pub
```

**Copy the entire output** - it should look like:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... your_email@example.com
```

## Step 6: Add SSH Key to GitHub

1. Go to GitHub: https://github.com/settings/keys
2. Click **"New SSH key"**
3. Fill in:
   - **Title**: Give it a descriptive name (e.g., "Dev Machine - Ubuntu")
   - **Key**: Paste the public key you copied in Step 5
4. Click **"Add SSH key"**
5. Enter your GitHub password if prompted

## Step 7: Test the Connection

```bash
ssh -T git@github.com
```

You should see:
```
Hi username! You've successfully authenticated, but GitHub does not provide shell access.
```

If you see a warning about authenticity, type `yes` to continue.

## Step 8: Update Your Git Remote to Use SSH

```bash
cd /home/devpup/Desktop/testnet-control-panel
git remote set-url origin git@github.com:synergy-network-hq/testnet-control-panel.git
git remote -v  # Verify the change
```

## Step 9: Pull Changes

```bash
git fetch origin
git pull origin main  # or 'master', depending on the default branch
```

## Troubleshooting

### If SSH agent isn't running:
```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519  # or id_rsa
```

### If you get "Permission denied (publickey)":
- Make sure you added the **public** key (`.pub` file) to GitHub, not the private key
- Verify the key was added: `ssh-add -l`
- Check GitHub settings: https://github.com/settings/keys

### To see your public key again:
```bash
cat ~/.ssh/id_ed25519.pub
# or
cat ~/.ssh/id_rsa.pub
```

### To list all keys in your SSH agent:
```bash
ssh-add -l
```

