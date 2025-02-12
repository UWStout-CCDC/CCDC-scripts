# Splunk Specific Scripts/Files

## Usage
### Download script
```
wget https://tinyurl.com/yx3pmm9m -O init-splunk.sh --no-check-certificate
```

### Make executable and run
```
chmod +x init-splunk.sh
./init-splunk.sh
```

### Script Options
* Manually create backup
```
./init-splunk.sh backup
```
* Restore most recent backup
```
./init-splunk.sh restore
```