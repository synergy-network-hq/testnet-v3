#!/bin/bash
# Install API router configuration file

sudo cp /opt/synergy/synergy-testnet/api.synergy-network.io /etc/nginx/sites-available/api.synergy-network.io
sudo chown root:synergydev /etc/nginx/sites-available/api.synergy-network.io
sudo chmod 664 /etc/nginx/sites-available/api.synergy-network.io

# Create symlink if not exists
if [ ! -L /etc/nginx/sites-enabled/api.synergy-network.io ]; then
    sudo ln -s /etc/nginx/sites-available/api.synergy-network.io /etc/nginx/sites-enabled/api.synergy-network.io
    echo "Created symlink in sites-enabled"
else
    echo "Symlink already exists"
fi

echo "API router configuration installed!"
ls -la /etc/nginx/sites-available/api.synergy-network.io
