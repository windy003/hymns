cp hymn-NLI.service /etc/systemd/system/hymn-NLI.service
systemctl daemon-reload
systemctl enable hymn-NLI.service
systemctl start hymn-NLI.service