cp hymn-NNL.service /etc/systemd/system/hymn-NNL.service
systemctl daemon-reload
systemctl enable hymn-NNL.service
systemctl start hymn-NNL.service