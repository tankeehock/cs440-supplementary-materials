# Finding subdomains with Cert Spotter

```
export TARGET="smu.edu.sg"
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" > $TARGET.ct.logs
cat $TARGET.ct.logs | jq -r '.[].dns_names[]' | grep $TARGET | sort -u
```