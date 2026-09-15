#!/bin/bash
# Fix nginx configuration file permissions to allow synergydev group to write

# Change ownership to root:synergydev
sudo chown root:synergydev /etc/nginx/sites-available/*.conf
sudo chown root:synergydev /etc/nginx/sites-available/api.synergy-network.io

# Set permissions to allow group write
sudo chmod 664 /etc/nginx/sites-available/*.conf
sudo chmod 664 /etc/nginx/sites-available/api.synergy-network.io

echo "✅ Nginx configuration file permissions fixed!"
echo "   Files are now writable by the synergydev group"
