#!/bin/bash
# Fix nginx configuration file permissions to allow editing

# Change ownership to root:synergydev and add group write permissions
sudo chown root:synergydev /etc/nginx/sites-available/synergy-network.io-subdomains.conf
sudo chmod 664 /etc/nginx/sites-available/synergy-network.io-subdomains.conf

# Also fix the main portal config if it exists
if [ -f /etc/nginx/sites-available/synergy-network.io.conf ]; then
    sudo chown root:synergydev /etc/nginx/sites-available/synergy-network.io.conf
    sudo chmod 664 /etc/nginx/sites-available/synergy-network.io.conf
fi

# Fix the API router config if it exists
if [ -f /etc/nginx/sites-available/api.synergy-network.io ]; then
    sudo chown root:synergydev /etc/nginx/sites-available/api.synergy-network.io
    sudo chmod 664 /etc/nginx/sites-available/api.synergy-network.io
fi

# Fix the letsencrypt-acme config if it exists
if [ -f /etc/nginx/sites-available/letsencrypt-acme.conf ]; then
    sudo chown root:synergydev /etc/nginx/sites-available/letsencrypt-acme.conf
    sudo chmod 664 /etc/nginx/sites-available/letsencrypt-acme.conf
fi

echo "Permissions fixed! You should now be able to edit the nginx configuration files."
ls -la /etc/nginx/sites-available/synergy-network.io-subdomains.conf
