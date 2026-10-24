curl -L -o data/ip2region_v6.xdb \
    https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb
  
curl -L -o data/ip2region_v4.xdb \
    https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb  
  
systemctl restart hymn-NLI.service    hymn-NNL.service