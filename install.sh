#!/bin/bash
echo "Downloading Androguard release"
wget https://github.com/androguard/androguard/archive/v2.0.tar.gz
tar -xvzf v2.0.tar.gz
mv androguard-2.0 androguard
echo "Cloning SAAF"
git clone https://github.com/programa-stic/SAAF
mv SAAF SAAF-MODULE
echo "Configuring SAAF"
cp saaf-configuration/backtracking-patterns.xml SAAF-MODULE/conf/backtracking-patterns.xml
cp saaf-configuration/saaf.conf SAAF-MODULE/conf/saaf.conf
cp saaf-configuration/log4j.properties SAAF-MODULE/conf/log4j.properties
cp saaf-configuration/xml.stg SAAF-MODULE/templates/xml.stg
cp SAAF-MODULE/releases/SAAF-v1.jar SAAF-MODULE/SAAF.jar
