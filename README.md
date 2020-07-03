# SFTP Terraform solution that supports both user/password and user/public-ssh-key authorization

## Intro

In computing, the SSH File Transfer Protocol (also Secure File Transfer Protocol, or SFTP) is a network protocol that provides file access, file transfer, and file management over any reliable data stream. It was designed by the Internet Engineering Task Force (IETF) as an extension of the Secure Shell protocol (SSH) version 2.0 to provide secure file transfer capabilities. This protocol assumes that it is run over a secure channel, such as SSH, that the server has already authenticated the client, and that the identity of the client user is available to the protocol.

FTPS (also known as FTPES, FTP-SSL, and FTP Secure) is an extension to the commonly used File Transfer Protocol (FTP) that adds support for the Transport Layer Security (TLS) and, formerly, the Secure Sockets Layer (SSL, which is now prohibited by RFC7568) cryptographic protocols. FTPS should not be confused with the SSH File Transfer Protocol (SFTP), a secure file transfer subsystem for the Secure Shell (SSH) protocol with which it is not compatible. It is a common misconception to think FTP over SSH is FTP tunneled over SSH. In fact, SFTP and FTPS are entirely different protocols. In FTP over SSH, the protocol messages correspond to disk operations rather than commands.

AWS Transfer Service for SFTP supports standard SFTP clients (e.g. WinSCP, ssh, Filezilla, Cyberduck).

When a home directory is set to "Restricted", your users will not be able to access anything outside of that folder, nor will they be able to see the S3 bucket or folder name.


## Useful links:

[Enable Password Authentication for AWS Transfer for SfTP using AWS Secrets Manager](https://aws.amazon.com/blogs/storage/enable-password-authentication-for-aws-transfer-for-sftp-using-aws-secrets-manager/)

[AWS SFTP User Guide](https://docs.aws.amazon.com/transfer/latest/userguide/what-is-aws-transfer-for-sftp.html)

[Simplify your AWS SFTP Structure with chroot and Logical Directories](https://aws.amazon.com/blogs/storage/simplify-your-aws-sftp-structure-with-chroot-and-logical-directories/)

[Using AWS SFTP Logical Directories](https://aws.amazon.com/blogs/storage/using-aws-sftp-logical-directories-to-build-a-simple-data-distribution-service/)

[Accessing Secrets across accounts](https://aws.amazon.com/blogs/security/how-to-access-secrets-across-aws-accounts-by-attaching-resource-based-policies/)


## Deploy Resources

* Create a public / private key pair with keygen and add the public key to secret/secrets-sftp-user1.json files
* Run Terraform to set up resources in AWS:
```
terraform init
terraform apply -auto-approve
```
* Set up two subfolders /sftp-user1 (containing file t1) and /sftp-user2 (containing file t2). If the folders are not there, sftp connect would not work!
```
SFTP_AWS_ACCOUNT_NO=094033154904
SFTP_BUCKET="sftp-bucket-${SFTP_AWS_ACCOUNT_NO}"
aws s3 cp t1 s3://${SFTP_BUCKET}/sftp-user1/
aws s3 cp t2 s3://${SFTP_BUCKET}/sftp-user2/
```
* Create secrets
```
cd secrets
source secrets/create-secrets.sh
```

## Test authentication with password

```
aws --region="eu-west-1" transfer test-identity-provider --server-id s-a4709e0516384f829 --user-name sftp-user1 --user-password mySecretPassword 
```


## Test with user1 and his private key - user1 has rw access to <bucket>/sftp-user1 and read access to <bucket>/sftp-user2<br>(replace arn of first command)

```
sftp -i ~/.ssh/id_rsa sftp-user1@s-0158e2bbbc9c436fa.server.transfer.eu-west-1.amazonaws.com
ls
cd sftp-user1
lls
get t1
lls
rm t1
ls
put t1
ls
cd sftp-user2
lls
get t2
lls
rm t2
ls
put t2
ls
```


## Test with user2 and his password - user2 has rw access to <bucket>/sftp-user2 and read access to <bucket>/sftp-user1 <br>(replace arn of first command)

```
sftp sftp-user2@s-94c409bbf5d8457a9.server.transfer.eu-west-1.amazonaws.com
ls
cd sftp-user1
lls
get t1
lls
rm t1
ls
put t1
ls
cd sftp-user2
lls
get t2
lls
rm t2
ls
put t2
ls
```


## Troubleshooting

Reasons why it does not work:
* Configuration in AWS Secrets Manager is wrong: check bucket name, folders, permissions etc.
* RSA host key differs: delete it from ~/.ssh/known_hosts
* S3 folder paths do not exist: add some test files to S3 folders
* VPN might block traffic: turn VPN off and try again
