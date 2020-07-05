# Substitute $SFTP_AWS_ACCOUNT_NO first (for macOS use sed -i "" -e ..., for Linux it is sed -i -e ...)
SFTP_AWS_ACCOUNT_NO=094033154904
echo "\$SFTP_AWS_ACCOUNT_NO is $SFTP_AWS_ACCOUNT_NO"
SFTP_BUCKET="sftp-bucket-${SFTP_AWS_ACCOUNT_NO}"
echo "\$SFTP_BUCKET is $SFTP_BUCKET"
sed -i .bak -e "s/\\\$SFTP_BUCKET/$SFTP_BUCKET/g" secrets-resource-based-policy.json
sed -i .bak -e "s/\\\$SFTP_AWS_ACCOUNT_NO/$SFTP_AWS_ACCOUNT_NO/g" secrets-resource-based-policy.json
sed -i .bak -e "s/\\\$SFTP_BUCKET/$SFTP_BUCKET/g" secrets-sftp-user1.json
sed -i .bak -e "s/\\\$SFTP_AWS_ACCOUNT_NO/$SFTP_AWS_ACCOUNT_NO/g" secrets-sftp-user1.json
sed -i .bak -e "s/\\\$SFTP_BUCKET/$SFTP_BUCKET/g" secrets-sftp-user2.json
sed -i .bak -e "s/\\\$SFTP_AWS_ACCOUNT_NO/$SFTP_AWS_ACCOUNT_NO/g" secrets-sftp-user2.json
aws secretsmanager create-secret --name /SFTP/sftp-user1 --description 'sftp user1 with rw access for its own folder and ro access for other folders' --secret-string file://secrets-sftp-user1.json
aws secretsmanager create-secret --name /SFTP/sftp-user2 --description 'sftp user2 with rw access for its own folder and ro access for other folders' --secret-string file://secrets-sftp-user2.json
aws secretsmanager create-secret --name /SFTP/sftp-user3 --description 'sftp user3 with rw access for its own folder' --secret-string file://secrets-sftp-user3.json

# aws secretsmanager get-secret-value --secret-id /SFTP/sftp-user1
# aws secretsmanager get-secret-value --secret-id /SFTP/sftp-user2
# aws secretsmanager put-secret-value --secret-id /SFTP/sftp-user1 --secret-string file://secrets-sftp-user1.json
# aws secretsmanager put-secret-value --secret-id /SFTP/sftp-user2 --secret-string file://secrets-sftp-user2.json

# pbpaste|jq . >secrets-resource-based-policy.json
# aws secretsmanager put-resource-policy --secret-id /SFTP/sftp-user2 --resource-policy file://secrets-resource-based-policy.json
# aws secretsmanager get-resource-policy --with-decryption --secret-id /SFTP/sftp-user2

# aws ssm put-parameter --name /SFTP/sftp-user1 --type SecureString --tier Standard --overwrite --description 'sftp user1 with rw access for its own folder and ro access for other folders' --value file://secrets-sftp-user1.json
# aws ssm put-parameter --name /SFTP/sftp-user2 --type SecureString --tier Standard --overwrite --description 'sftp user2 with rw access for its own folder and ro access for other folders' --value file://secrets-sftp-user2.json
# aws ssm put-parameter --name /SFTP/sftp-user3 --key-id 820bf483-b550-4661-80cc-7fbc7a606e13 --type SecureString --tier Standard --overwrite --description 'sftp user1 with rw access for its own folder and ro access for other folders' --value file://secrets-sftp-user1.json

# echo "Restore original configuration files"
# mv secrets-sftp-user1.json.bak secrets-sftp-user1.json
# mv secrets-sftp-user2.json.bak secrets-sftp-user2.json
