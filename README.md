Implemented Encrypted File System in java, where each file will be split into chunks, encrypted and stored in the FS.
Each file operation needs password validation, where SHA384 hash of password and SALT is used as randomizer.
Each file chunk is 1024 precizely bytes in size, padding is done if it's less than that.
HMAC of the encrypted contents is generated to ensure the integrity of the contents.
File operations are done efficiently, thus best in terms of read / write efficiency and encryption / decryption.
