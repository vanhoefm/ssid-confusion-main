#!/bin/bash

cd data

# https://enterprise-wifi.net/user/API.php?action=downloadInstaller&api_version=2&lang=en&device=linux&profile=214

# Download all the profiles
wget 'https://enterprise-wifi.net/user/API.php?action=downloadInstaller&api_version=2&lang=en&device=linux&profile='{0..1000}

