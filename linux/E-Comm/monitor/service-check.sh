# Check if the index.php hash file exists, in the /ccdc/tmp directory
if [ ! -f /ccdc/tmp/index.php.hash ]; then
  echo "Index.php hash file does not exist, creating now..."
  # Create a hash of the index.php file
  curl -s $BASE_URL/linux/E-Comm/index.php | sha256sum | cut -d ' ' -f 1 > /ccdc/tmp/index.php.hash
fi

while true
do
    # Check if the index.php file has been modified, and alert the user that the service has been compromised
    if [ "$(curl -s $BASE_URL/linux/E-Comm/index.php | sha256sum | cut -d ' ' -f 1)" != "$(cat /ccdc/tmp/index.php.hash)" ]; then
        echo "ALERT: The index.php file has been modified!"
        echo "ALERT: The service has been compromised!"
        echo "ALERT: Please investigate immediately!"
        exit 1
    fi
    sleep 5
done