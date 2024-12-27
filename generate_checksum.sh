#!/bin/bash

# Set paths and variables
XCFRAMEWORK_PATH="/Users/harikagangireddy/Desktop/TestPrivateFramework.xcframework"
OUTPUT_FILE="encrypted.txt"
CERTIFICATE_PATH="public_key.pem"
IV="000102030405060708090a0b0c0d0e0f"
JSON_FILE="checksum.json"
OUTPUT_FILE_1="swift.txt"
ENCRYPTED_FILE="checksums.enc"

# Generate static AES key (use a secure method in production)
AES_KEY="2b7e151628aed2a6abf7158809cf4f3c"
AES_KEY_BIN=$(echo "$AES_KEY" | xxd -r -p)
IV_BIN=$(echo "$IV" | xxd -r -p)
# Encrypt the AES key with the public RSA key
openssl pkeyutl -encrypt -inkey "$CERTIFICATE_PATH" -pubin -in <(echo -n "$AES_KEY" | xxd -r -p) -out aes_key.enc
if [ $? -ne 0 ]; then
    echo "Failed to encrypt AES key."
    exit 1
fi

# Generate checksums
echo "{}" > "$JSON_FILE"
find "$XCFRAMEWORK_PATH" -type f -name "TestPrivateFramework" | while read -r binary; do
    arch=$(echo "$binary" | awk -F'/' '{print $(NF-2)}')
    checksum=$(shasum -a 256 "$binary" | awk '{print $1}')
    jq --arg arch "$arch" --arg checksum "$checksum" '. + {($arch): $checksum}' "$JSON_FILE" > temp.json && mv temp.json "$JSON_FILE"
done

# Encrypt the JSON file using AES-256-CBC
openssl enc -aes-128-cbc -K "$AES_KEY" -iv "$IV" -in "$JSON_FILE" -out "$ENCRYPTED_FILE"
if [ $? -ne 0 ]; then
    echo "Failed to encrypt JSON file."
    exit 1
fi
# Convert encrypted AES key to Base64
AES_KEY_BASE64=$(cat aes_key.enc | base64)

# Convert encrypted JSON data to Base64
ENCRYPTED_DATA_BASE64=$(cat "$ENCRYPTED_FILE" | base64)

# Combine Base64-encoded AES key and encrypted data with a delimiter (e.g., `|`)
echo "${AES_KEY_BASE64}|${ENCRYPTED_DATA_BASE64}" > "$OUTPUT_FILE"
echo "${ENCRYPTED_DATA_BASE64}" > "$OUTPUT_FILE_1"

# Cleanup temporary files
# rm -f "$JSON_FILE" "$ENCRYPTED_FILE" aes_key.enc

echo "Process completed successfully. Output saved to $OUTPUT_FILE."

