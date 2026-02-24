#!/bin/bash

# Configuration paths - stores database files for folder/file listings
# Use absolute paths that won't be affected by encryption
CONFIG_DIR="/etc/cryptoconfig"
pathToFolder="$CONFIG_DIR/folders.txt"
pathToFile="$CONFIG_DIR/files.txt"
pathToSsl="$CONFIG_DIR/ssl_pass.txt"  # Store SSL password hash
pathToGpg="$CONFIG_DIR/gpg_pass.txt"  # Store GPG password hash
pathToAes="$CONFIG_DIR/aes_pass.txt"  # Store AES password hash
pathToRsaPublic="$CONFIG_DIR/rsa_public.pem"  # RSA public key
pathToRsaPrivate="$CONFIG_DIR/rsa_private.pem" # RSA private key
pathToGen="$CONFIG_DIR/gen.txt"
pathToEnc="$CONFIG_DIR/enc.txt"
pathToCryptoType="$CONFIG_DIR/crypto_type.txt"  # Store current crypto type

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Global variables
pass=""        # Stores hashed password for hash-based renaming operations
ssl_pass_hash="" # Stores hashed SSL password for verification
gpg_pass_hash="" # Stores hashed GPG password for verification
aes_pass_hash="" # Stores hashed AES password for verification
crypto_pass_plain="" # Stores plain password for current crypto method
hash="sha256"     # Current hash algorithm being used (md5, sha1, sha256, sha512)
operation_mode="" # Track current operation mode
crypto_type="ssl"  # Default crypto type (ssl, gpg, aes, or rsa)
rsa_key_size=2048 # RSA key size in bits

# Load saved crypto type if exists
if [[ -f "$pathToCryptoType" ]]; then
    crypto_type=$(cat "$pathToCryptoType")
fi

# Function to check if a string matches the current hash algorithm's length
isaEncOne() {
    local name="$1"
    case ${hash} in
        "md5")
            [[ ${#name} -eq 32 ]] && echo 1 || echo 0
            ;;
        "sha1")
            [[ ${#name} -eq 40 ]] && echo 1 || echo 0
            ;;
        "sha256")
            [[ ${#name} -eq 64 ]] && echo 1 || echo 0
            ;;
        "sha512")
            [[ ${#name} -eq 128 ]] && echo 1 || echo 0
            ;;
        *)
            echo 0
            ;;
    esac
}

# Function to set crypto type
set_crypto_type() {
    local new_type="$1"
    if [[ "$new_type" != "ssl" && "$new_type" != "gpg" && "$new_type" != "aes" && "$new_type" != "rsa" ]]; then
        echo "Invalid crypto type. Use 'ssl', 'gpg', 'aes', or 'rsa'"
        return 1
    fi
    crypto_type="$new_type"
    echo "$crypto_type" > "$pathToCryptoType"
    echo "Crypto type set to: $crypto_type"
}

# Function to generate RSA key pair
generate_rsa_keys() {
    if [[ -f "$pathToRsaPrivate" ]] && [[ -f "$pathToRsaPublic" ]]; then
        echo "RSA keys already exist. Overwrite? (y/n): "
        read -r answer
        if [[ "$answer" != "y" ]]; then
            return 0
        fi
    fi
    
    echo "Generating RSA key pair (${rsa_key_size} bits)..."
    
    # Generate private key
    openssl genrsa -out "$pathToRsaPrivate" "$rsa_key_size" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        echo "Failed to generate RSA private key"
        return 1
    fi
    
    # Extract public key
    openssl rsa -in "$pathToRsaPrivate" -pubout -out "$pathToRsaPublic" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        echo "Failed to extract RSA public key"
        return 1
    fi
    
    # Set secure permissions
    chmod 600 "$pathToRsaPrivate"
    chmod 644 "$pathToRsaPublic"
    
    echo "RSA key pair generated successfully"
    echo "Private key: $pathToRsaPrivate"
    echo "Public key: $pathToRsaPublic"
    
    return 0
}

# Function to set password with hidden input
setPass() {
    local char
    local input_pass=""
    local purpose="$1"  # "hash", "ssl", "gpg", "aes", or "rsa"
    
    # For RSA, we don't need a password (key-based)
    if [[ "$purpose" == "rsa" ]]; then
        # Check if RSA keys exist, generate if not
        if [[ ! -f "$pathToRsaPrivate" ]] || [[ ! -f "$pathToRsaPublic" ]]; then
            echo "RSA keys not found. Generating new key pair..."
            generate_rsa_keys || return 1
        fi
        crypto_pass_plain=""  # No password for RSA
        return 0
    fi
    
    printf "Enter ${purpose} password: "
    while IFS= read -r -s -n1 char; do
        if [[ $char = "" ]]; then
            printf "\n"
            break
        elif [[ $char = $'\177' ]]; then
            if [[ -n $input_pass ]]; then
                input_pass=${input_pass%?}
                printf '\b \b'
            fi
        else
            input_pass+=$char
            printf "*"
        fi
    done
    echo
    
    if [[ -z $input_pass ]]; then
        echo "Password cannot be empty"
        return 1
    fi
    
    # Store based on purpose
    if [[ "$purpose" == "ssl" ]]; then
        # For SSL, store both plain for immediate use and hash for verification
        crypto_pass_plain="$input_pass"
        ssl_pass_hash=$(echo -n "$input_pass" | sha256sum | cut -d " " -f1)
        # Save SSL password hash for verification during decryption
        echo "$ssl_pass_hash" > "$pathToSsl"
    elif [[ "$purpose" == "gpg" ]]; then
        # For GPG, store both plain for immediate use and hash for verification
        crypto_pass_plain="$input_pass"
        gpg_pass_hash=$(echo -n "$input_pass" | sha256sum | cut -d " " -f1)
        # Save GPG password hash for verification during decryption
        echo "$gpg_pass_hash" > "$pathToGpg"
    elif [[ "$purpose" == "aes" ]]; then
        # For AES, store both plain for immediate use and hash for verification
        crypto_pass_plain="$input_pass"
        aes_pass_hash=$(echo -n "$input_pass" | sha256sum | cut -d " " -f1)
        # Save AES password hash for verification during decryption
        echo "$aes_pass_hash" > "$pathToAes"
    else
        # For hash-based renaming
        crypto_pass_plain=""  # Clear crypto password when setting hash password
        pass=$(echo -n "$input_pass" | ${hash}sum | cut -d " " -f1)
    fi
}

# Verify password against stored hash
verify_crypto_pass() {
    local pass_type="$1"
    local pass_file
    local stored_hash
    local input_hash
    
    if [[ "$pass_type" == "ssl" ]]; then
        pass_file="$pathToSsl"
    elif [[ "$pass_type" == "gpg" ]]; then
        pass_file="$pathToGpg"
    elif [[ "$pass_type" == "aes" ]]; then
        pass_file="$pathToAes"
    elif [[ "$pass_type" == "rsa" ]]; then
        # For RSA, we verify keys exist instead of password
        if [[ ! -f "$pathToRsaPrivate" ]]; then
            echo "RSA private key not found"
            return 1
        fi
        return 0
    else
        echo "Invalid password type"
        return 1
    fi
    
    if [[ ! -f "$pass_file" ]]; then
        echo "No $pass_type password record found. Did you encrypt with this tool?"
        return 1
    fi
    
    stored_hash=$(cat "$pass_file")
    input_hash=$(echo -n "$crypto_pass_plain" | sha256sum | cut -d " " -f1)
    
    if [[ "$input_hash" != "$stored_hash" ]]; then
        echo "Incorrect $pass_type password!"
        return 1
    fi
    return 0
}

# Helper functions for path manipulation
getHowmanySlashes() {
    echo "$1" | grep -o "/" | wc -l
}

getROOT() {
    local howmanySlashes=$(getHowmanySlashes "$1")
    if [[ $howmanySlashes -eq 0 ]]; then
        echo "."
    else
        echo "$1" | cut -d "/" -f1-$((howmanySlashes))
    fi
}

getFile() {
    local howmanySlashes=$(getHowmanySlashes "$1")
    if [[ $howmanySlashes -eq 0 ]]; then
        echo "$1"
    else
        echo "$1" | cut -d "/" -f$((howmanySlashes + 1))
    fi
}

# Core hash function for renaming
encrypt() {
    local file="$1"
    if [[ -z $pass ]]; then
        echo "Hash password not set" >&2
        return 1
    fi
    echo -n "$pass$file" | ${hash}sum | cut -d " " -f1
}

# Database maintenance functions - using absolute paths that won't be affected
saveDatabases() {
    # Save current file structure BEFORE any encryption
    echo "Saving directory structure to database..."
    > "$pathToFolder"
    > "$pathToFile"
    
    # Save all directories
    find . -type d ! -path "." 2>/dev/null | sed 's/^\.\///' | while read -r item; do
        if [[ -n "$item" && "$item" != "." && "$item" != ".." ]]; then
            echo "$item" >> "$pathToFolder"
        fi
    done
    
    # Save all files
    find . -type f 2>/dev/null | sed 's/^\.\///' | while read -r item; do
        if [[ -n "$item" ]]; then
            echo "$item" >> "$pathToFile"
        fi
    done
    
    echo "Database saved: $(wc -l < "$pathToFile") files, $(wc -l < "$pathToFolder") folders"
}

# Function to remove empty folders recursively
remove_empty_folders() {
    echo "=== REMOVING EMPTY FOLDERS RECURSIVELY ==="
    
    local removed_count=0
    local pass_count=0
    local max_passes=10  # Prevent infinite loops
    
    echo "Scanning for empty folders..."
    
    # Keep scanning until no more empty folders are found
    while [[ $pass_count -lt $max_passes ]]; do
        local found_empty=0
        
        # Find all directories (deepest first) that are empty
        while IFS= read -r dir; do
            if [[ -d "$dir" ]]; then
                # Check if directory is empty (no files, no subdirectories)
                if [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
                    echo "Removing empty folder: $dir"
                    rmdir "$dir" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        ((removed_count++))
                        ((found_empty++))
                    fi
                fi
            fi
        done < <(find . -type d 2>/dev/null | sort -r)  # Reverse sort to process deepest first
        
        # If no empty folders found in this pass, we're done
        if [[ $found_empty -eq 0 ]]; then
            break
        fi
        
        ((pass_count++))
    done
    
    if [[ $removed_count -gt 0 ]]; then
        echo "Removed $removed_count empty folders"
    else
        echo "No empty folders found"
    fi
    
    return 0
}

# SSL Encryption
enc_ssl() {
    if [[ -z $crypto_pass_plain ]]; then
        setPass "ssl" || return 1
    fi
    
    local bits=256
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local files=()
    local encrypted_count=0
    
    # Filter out .ssl files and config files
    for item in "${tree[@]}"; do
        if [[ "$item" != *.ssl && "$item" != "$CONFIG_DIR"* ]]; then
            files+=("$item")
        fi
    done
    
    echo "Found ${#files[@]} files to encrypt with SSL"
    
    if [[ ${#files[@]} -gt 0 ]]; then
        for file in "${files[@]}"; do
            if [[ -f "$file" ]]; then
                echo "SSL Encrypting: $file"
                if openssl enc -aes-${bits}-cbc -salt -in "$file" -out "${file}.ssl" -k "$crypto_pass_plain" 2>/dev/null; then
                    rm "$file"
                    echo "  -> ${file}.ssl"
                    ((encrypted_count++))
                else
                    echo "  Failed to encrypt: $file"
                fi
            fi
        done
        echo "SSL Encryption complete: $encrypted_count files encrypted"
    else
        echo "No files to encrypt with SSL"
    fi
}

# SSL Decryption
dec_ssl() {
    if [[ -z $crypto_pass_plain ]]; then
        setPass "ssl" || return 1
    fi
    
    # Verify password against stored hash
    verify_crypto_pass "ssl" || return 1
    
    local bits=256
    local tree=( $(find . -name "*.ssl" -type f 2>/dev/null | sed 's/^\.\///') )
    local decrypted_count=0
    
    echo "Found ${#tree[@]} SSL files to decrypt"
    
    for file in "${tree[@]}"; do
        local output="${file%.ssl}"
        echo "Decrypting: $file -> $output"
        if openssl enc -d -aes-256-cbc -in "$file" -out "$output" -k "$crypto_pass_plain" 2>/dev/null; then
            rm "$file"
            echo "  Decrypted: $file"
            ((decrypted_count++))
        else
            echo "  Failed to decrypt: $file (wrong password?)"
        fi
    done
    echo "SSL Decryption complete: $decrypted_count files decrypted"
    
    # Remove empty folders after decryption
    remove_empty_folders
}

# GPG Encryption
enc_gpg() {
    if [[ -z $crypto_pass_plain ]]; then
        setPass "gpg" || return 1
    fi
    
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local files=()
    local encrypted_count=0
    
    # Filter out .gpg files and config files
    for item in "${tree[@]}"; do
        if [[ "$item" != *.gpg && "$item" != "$CONFIG_DIR"* ]]; then
            files+=("$item")
        fi
    done
    
    echo "Found ${#files[@]} files to encrypt with GPG"
    
    if [[ ${#files[@]} -gt 0 ]]; then
        for file in "${files[@]}"; do
            if [[ -f "$file" ]]; then
                echo "GPG Encrypting: $file"
                # Use symmetric encryption with AES256
                if echo "$crypto_pass_plain" | gpg --batch --yes --passphrase-fd 0 \
                    --symmetric --cipher-algo AES256 -o "${file}.gpg" "$file" 2>/dev/null; then
                    rm "$file"
                    echo "  -> ${file}.gpg"
                    ((encrypted_count++))
                else
                    echo "  Failed to encrypt: $file"
                fi
            fi
        done
        echo "GPG Encryption complete: $encrypted_count files encrypted"
    else
        echo "No files to encrypt with GPG"
    fi
}

# GPG Decryption
dec_gpg() {
    if [[ -z $crypto_pass_plain ]]; then
        setPass "gpg" || return 1
    fi
    
    # Verify password against stored hash
    verify_crypto_pass "gpg" || return 1
    
    local tree=( $(find . -name "*.gpg" -type f 2>/dev/null | sed 's/^\.\///') )
    local decrypted_count=0
    
    echo "Found ${#tree[@]} GPG files to decrypt"
    
    for file in "${tree[@]}"; do
        local output="${file%.gpg}"
        echo "Decrypting: $file -> $output"
        if echo "$crypto_pass_plain" | gpg --batch --yes --passphrase-fd 0 \
            --decrypt -o "$output" "$file" 2>/dev/null; then
            rm "$file"
            echo "  Decrypted: $file"
            ((decrypted_count++))
        else
            echo "  Failed to decrypt: $file (wrong password?)"
        fi
    done
    echo "GPG Decryption complete: $decrypted_count files decrypted"
    
    # Remove empty folders after decryption
    remove_empty_folders
}

# AES Encryption (using OpenSSL with PBKDF2 for better security)
enc_aes() {
    if [[ -z $crypto_pass_plain ]]; then
        setPass "aes" || return 1
    fi
    
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local files=()
    local encrypted_count=0
    
    # Filter out .aes files and config files
    for item in "${tree[@]}"; do
        if [[ "$item" != *.aes && "$item" != "$CONFIG_DIR"* ]]; then
            files+=("$item")
        fi
    done
    
    echo "Found ${#files[@]} files to encrypt with AES-256-CBC (PBKDF2)"
    
    if [[ ${#files[@]} -gt 0 ]]; then
        for file in "${files[@]}"; do
            if [[ -f "$file" ]]; then
                echo "AES Encrypting: $file"
                # Use AES-256-CBC with PBKDF2 for better key derivation
                if openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
                    -in "$file" -out "${file}.aes" -k "$crypto_pass_plain" 2>/dev/null; then
                    rm "$file"
                    echo "  -> ${file}.aes"
                    ((encrypted_count++))
                else
                    echo "  Failed to encrypt: $file"
                fi
            fi
        done
        echo "AES Encryption complete: $encrypted_count files encrypted"
    else
        echo "No files to encrypt with AES"
    fi
}

# AES Decryption
dec_aes() {
    if [[ -z $crypto_pass_plain ]]; then
        setPass "aes" || return 1
    fi
    
    # Verify password against stored hash
    verify_crypto_pass "aes" || return 1
    
    local tree=( $(find . -name "*.aes" -type f 2>/dev/null | sed 's/^\.\///') )
    local decrypted_count=0
    
    echo "Found ${#tree[@]} AES files to decrypt"
    
    for file in "${tree[@]}"; do
        local output="${file%.aes}"
        echo "Decrypting: $file -> $output"
        # Decrypt with PBKDF2
        if openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
            -in "$file" -out "$output" -k "$crypto_pass_plain" 2>/dev/null; then
            rm "$file"
            echo "  Decrypted: $file"
            ((decrypted_count++))
        else
            echo "  Failed to decrypt: $file (wrong password?)"
        fi
    done
    echo "AES Decryption complete: $decrypted_count files decrypted"
    
    # Remove empty folders after decryption
    remove_empty_folders
}

# RSA Encryption
enc_rsa() {
    # Ensure RSA keys exist
    if [[ ! -f "$pathToRsaPublic" ]]; then
        echo "RSA public key not found. Generating new key pair..."
        setPass "rsa" || return 1
    fi
    
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local files=()
    local encrypted_count=0
    
    # Filter out .rsa files and config files
    for item in "${tree[@]}"; do
        if [[ "$item" != *.rsa && "$item" != "$CONFIG_DIR"* ]]; then
            files+=("$item")
        fi
    done
    
    echo "Found ${#files[@]} files to encrypt with RSA (hybrid encryption)"
    echo "Note: RSA encrypts a random key, which encrypts the file (hybrid encryption)"
    
    if [[ ${#files[@]} -gt 0 ]]; then
        for file in "${files[@]}"; do
            if [[ -f "$file" ]]; then
                echo "RSA Encrypting: $file"
                
                # Generate random symmetric key
                local sym_key=$(openssl rand -hex 32)
                local iv=$(openssl rand -hex 16)
                
                # Encrypt the file with AES using the random key
                openssl enc -aes-256-cbc -salt -pbkdf2 -iter 10000 \
                    -in "$file" -out "${file}.aes.tmp" -K "$sym_key" -iv "$iv" 2>/dev/null
                
                if [[ $? -eq 0 ]]; then
                    # Encrypt the symmetric key with RSA public key
                    echo -n "$sym_key:$iv" | openssl rsautl -encrypt -pubin -inkey "$pathToRsaPublic" \
                        -out "${file}.key.tmp" 2>/dev/null
                    
                    if [[ $? -eq 0 ]]; then
                        # Combine encrypted key and encrypted file
                        cat "${file}.key.tmp" "${file}.aes.tmp" > "${file}.rsa"
                        
                        # Clean up temp files
                        rm -f "${file}.aes.tmp" "${file}.key.tmp"
                        rm "$file"
                        
                        echo "  -> ${file}.rsa"
                        ((encrypted_count++))
                    else
                        echo "  Failed to encrypt key for: $file"
                        rm -f "${file}.aes.tmp"
                    fi
                else
                    echo "  Failed to encrypt: $file"
                fi
            fi
        done
        echo "RSA Encryption complete: $encrypted_count files encrypted"
    else
        echo "No files to encrypt with RSA"
    fi
}

# RSA Decryption
dec_rsa() {
    # Ensure RSA private key exists
    if [[ ! -f "$pathToRsaPrivate" ]]; then
        echo "RSA private key not found"
        return 1
    fi
    
    local tree=( $(find . -name "*.rsa" -type f 2>/dev/null | sed 's/^\.\///') )
    local decrypted_count=0
    
    echo "Found ${#tree[@]} RSA files to decrypt"
    
    for file in "${tree[@]}"; do
        local output="${file%.rsa}"
        echo "Decrypting: $file -> $output"
        
        # Get file sizes
        local file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
        
        # RSA key size in bytes (2048 bits = 256 bytes)
        local key_size=256
        
        # Extract encrypted key (first key_size bytes)
        dd if="$file" of="${file}.key.tmp" bs=1 count=$key_size 2>/dev/null
        
        # Extract encrypted data (remaining bytes)
        dd if="$file" of="${file}.aes.tmp" bs=1 skip=$key_size 2>/dev/null
        
        # Decrypt the symmetric key with RSA private key
        local key_iv=$(openssl rsautl -decrypt -inkey "$pathToRsaPrivate" -in "${file}.key.tmp" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && [[ -n "$key_iv" ]]; then
            # Split key and IV
            local sym_key=$(echo "$key_iv" | cut -d: -f1)
            local iv=$(echo "$key_iv" | cut -d: -f2)
            
            # Decrypt the file with AES using the recovered key
            openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 \
                -in "${file}.aes.tmp" -out "$output" -K "$sym_key" -iv "$iv" 2>/dev/null
            
            if [[ $? -eq 0 ]]; then
                rm "$file" "${file}.key.tmp" "${file}.aes.tmp"
                echo "  Decrypted: $file"
                ((decrypted_count++))
            else
                echo "  Failed to decrypt data for: $file"
                rm -f "${file}.key.tmp" "${file}.aes.tmp"
            fi
        else
            echo "  Failed to decrypt key for: $file (wrong private key?)"
            rm -f "${file}.key.tmp" "${file}.aes.tmp"
        fi
    done
    echo "RSA Decryption complete: $decrypted_count files decrypted"
    
    # Remove empty folders after decryption
    remove_empty_folders
}

# Content encryption based on current crypto type
enc_content() {
    if [[ "$crypto_type" == "ssl" ]]; then
        enc_ssl
    elif [[ "$crypto_type" == "gpg" ]]; then
        enc_gpg
    elif [[ "$crypto_type" == "aes" ]]; then
        enc_aes
    else
        enc_rsa
    fi
}

# Content decryption based on current crypto type
dec_content() {
    if [[ "$crypto_type" == "ssl" ]]; then
        dec_ssl
    elif [[ "$crypto_type" == "gpg" ]]; then
        dec_gpg
    elif [[ "$crypto_type" == "aes" ]]; then
        dec_aes
    else
        dec_rsa
    fi
}

# Hash-based Filename Encryption
encFile01() {
    if [[ -z $pass ]]; then
        setPass "hash" || return 1
    fi

    local tree=( $(find . -type f 2>/dev/null | grep -v "^\./$(basename "$CONFIG_DIR")" | sed 's/^\.\///') )
    local renamed_count=0
    local ext
    
    for file in "${tree[@]}"; do
        local filename=$(getFile "$file")
        
        # Check if it's an encrypted content file
        if [[ "$file" == *.ssl ]] || [[ "$file" == *.gpg ]] || [[ "$file" == *.aes ]] || [[ "$file" == *.rsa ]]; then
            # Strip the extension
            if [[ "$file" == *.ssl ]]; then
                ext="ssl"
            elif [[ "$file" == *.gpg ]]; then
                ext="gpg"
            elif [[ "$file" == *.aes ]]; then
                ext="aes"
            else
                ext="rsa"
            fi
            local base="${filename%.$ext}"
            # Skip if already hashed
            if [[ $(isaEncOne ${base}) == 1 ]]; then
                continue
            fi
            local root=$(getROOT "$file")
            local C_base=$(encrypt "$base")
            echo "Renaming: $file -> $root/${C_base}.$ext"
            mv "$file" "$root/${C_base}.$ext" 2>/dev/null
            ((renamed_count++))
        else
            # Regular file
            if [[ $(isaEncOne ${filename}) == 1 ]]; then
                continue
            fi
            local root=$(getROOT "$file")
            local C_name=$(encrypt "$filename")
            echo "Renaming: $file -> $root/$C_name"
            mv "$file" "$root/$C_name" 2>/dev/null
            ((renamed_count++))
        fi
    done
    echo "Hash-based Rename complete: $renamed_count files renamed"
}

# Hash-based Filename Decryption
decFile01() {
    if [[ -z $pass ]]; then
        setPass "hash" || return 1
    fi

    if [[ ! -f "$pathToFile" ]]; then
        echo "Database file not found: $pathToFile"
        return 1
    fi
    
    # Read original names from database
    local allfiles=()
    while IFS= read -r line; do
        allfiles+=("$line")
    done < "$pathToFile"
    
    local tree=( $(find . -type f 2>/dev/null | grep -v "^\./$(basename "$CONFIG_DIR")" | sed 's/^\.\///') )
    local restored_count=0
    
    for current_file in "${tree[@]}"; do
        local current_name=$(getFile "$current_file")
        local current_path=$(getROOT "$current_file")
        
        # Handle encrypted content files
        local is_encrypted=false
        local enc_ext=""
        local base_name="$current_name"
        
        if [[ "$current_name" == *.ssl ]]; then
            is_encrypted=true
            enc_ext="ssl"
            base_name="${current_name%.ssl}"
        elif [[ "$current_name" == *.gpg ]]; then
            is_encrypted=true
            enc_ext="gpg"
            base_name="${current_name%.gpg}"
        elif [[ "$current_name" == *.aes ]]; then
            is_encrypted=true
            enc_ext="aes"
            base_name="${current_name%.aes}"
        elif [[ "$current_name" == *.rsa ]]; then
            is_encrypted=true
            enc_ext="rsa"
            base_name="${current_name%.rsa}"
        fi
        
        # Check if current name looks like a hash
        if [[ $(isaEncOne ${base_name}) == 1 ]]; then
            # Try to find matching original
            for original in "${allfiles[@]}"; do
                local orig_name=$(getFile "$original")
                local orig_path=$(getROOT "$original")
                local C_orig=$(encrypt "$orig_name")
                
                if [[ "$base_name" == "$C_orig" ]]; then
                    if [[ "$is_encrypted" == true ]]; then
                        # For encrypted content files, keep the extension
                        local target_name="${orig_name}.${enc_ext}"
                        local target_path="$orig_path"
                        
                        # Create directory if needed
                        if [[ "$current_path" != "$target_path" ]]; then
                            mkdir -p "$target_path"
                        fi
                        
                        echo "Restoring: $current_file -> $target_path/$target_name"
                        mv "$current_file" "$target_path/$target_name" 2>/dev/null
                    else
                        # Regular file
                        local target_path="$orig_path"
                        
                        # Create directory if needed
                        if [[ "$current_path" != "$target_path" ]]; then
                            mkdir -p "$target_path"
                        fi
                        
                        echo "Restoring: $current_file -> $target_path/$orig_name"
                        mv "$current_file" "$target_path/$orig_name" 2>/dev/null
                    fi
                    ((restored_count++))
                    break
                fi
            done
        fi
    done
    echo "Hash-based Name restoration complete: $restored_count files restored"
}

# Folder encryption
encFolder01() {
    if [[ -z $pass ]]; then
        setPass "hash" || return 1
    fi

    # Get all directories (deepest first)
    local tree=( $(find . -type d ! -path "." 2>/dev/null | grep -v "^\./$(basename "$CONFIG_DIR")" | sed 's/^\.\///' | awk '{print length, $0}' | sort -nr | cut -d' ' -f2-) )
    
    for folder_item in "${tree[@]}"; do
        local folder=$(getFile "$folder_item")
        
        # Skip if already hashed
        if [[ $(isaEncOne ${folder}) == 1 ]]; then
            continue
        fi
        
        local root=$(getROOT "$folder_item")
        local C_folder=$(encrypt "${folder}/")
        
        echo "Renaming folder: $folder_item -> $root/$C_folder"
        mv "$folder_item" "$root/$C_folder" 2>/dev/null
    done
}

# Folder decryption
decFolder01() {
    if [[ -z $pass ]]; then
        setPass "hash" || return 1
    fi

    if [[ ! -f "$pathToFolder" ]]; then
        echo "Database file not found: $pathToFolder"
        return 1
    fi

    local allfolders=()
    while IFS= read -r line; do
        allfolders+=("$line")
    done < "$pathToFolder"
    
    # Get all directories (deepest first)
    local tree=( $(find . -type d ! -path "." 2>/dev/null | grep -v "^\./$(basename "$CONFIG_DIR")" | sed 's/^\.\///' | awk '{print length, $0}' | sort -nr | cut -d' ' -f2-) )
    
    for current_folder in "${tree[@]}"; do
        local current_name=$(getFile "$current_folder")
        local current_path=$(getROOT "$current_folder")
        
        # Check if current name looks like a hash
        if [[ $(isaEncOne ${current_name}) == 1 ]]; then
            # Try to find matching original
            for original in "${allfolders[@]}"; do
                local orig_name=$(getFile "$original")
                local orig_path=$(getROOT "$original")
                local C_orig=$(encrypt "${orig_name}/")
                
                if [[ "$current_name" == "$C_orig" ]]; then
                    # Create target directory if needed
                    if [[ "$current_path" != "$orig_path" ]]; then
                        mkdir -p "$orig_path"
                    fi
                    
                    echo "Restoring folder: $current_folder -> $orig_path/$orig_name"
                    mv "$current_folder" "$orig_path/$orig_name" 2>/dev/null
                    break
                fi
            done
        fi
    done
}

# RSA key management commands
cmd_genrsa() {
    generate_rsa_keys
}

cmd_showrsa() {
    if [[ -f "$pathToRsaPublic" ]]; then
        echo "RSA Public Key:"
        cat "$pathToRsaPublic"
        echo ""
    fi
    if [[ -f "$pathToRsaPrivate" ]]; then
        echo "RSA Private Key (location): $pathToRsaPrivate"
        echo "Use with caution - this is your private key!"
    fi
}

# COMPLETE ENCRYPTION
encrypt_complete() {
    echo "=== COMPLETE ENCRYPTION PROCESS === $hash \& $crypto_type"
    echo "Step 1: Save database of original names"
    echo "--------------------------------------------------------"
    saveDatabases
    
    echo -e "\nStep 2: Content Encryption ($crypto_type)"
    echo "--------------------------------------------------------"
    enc_content
    
    echo -e "\nStep 3: Hash-based Filename Encryption"
    echo "--------------------------------------------------------"
    encFile01
    encFolder01
    
    echo -e "\n=== ENCRYPTION COMPLETE ==="
    echo "All files encrypted. To decrypt, use: $0 decrypt"
    echo "Database saved in: $CONFIG_DIR"
}

# COMPLETE DECRYPTION
decrypt_complete() {
    echo "=== COMPLETE DECRYPTION PROCESS ==="
    
    # First, ensure databases exist
    if [[ ! -f "$pathToFile" ]] || [[ ! -f "$pathToFolder" ]]; then
        echo "ERROR: Database files not found in $CONFIG_DIR"
        echo "Cannot restore original names without database."
        return 1
    fi
    
    echo "Step 1: Hash-based Filename Restoration"
    echo "--------------------------------------------------------"
    decFile01
    decFolder01
    
    echo -e "\nStep 2: Content Decryption ($crypto_type)"
    echo "--------------------------------------------------------"
    dec_content
    
    echo -e "\nStep 3: Clean up empty folders"
    echo "--------------------------------------------------------"
    remove_empty_folders
    
    echo -e "\n=== DECRYPTION COMPLETE ==="
    echo "All files restored to original state"
}

# Standalone empty folder removal command
cmd_remove_empty() {
    remove_empty_folders
}

# Main script execution
case "$1" in
    encrypt|main)
        encrypt_complete
        ;;
    decrypt|notmain)
        decrypt_complete
        ;;
    settype)
        if [[ -z $2 ]]; then
            echo "Current crypto type: $crypto_type"
            echo "Usage: $0 settype [ssl|gpg|aes|rsa]"
        else
            set_crypto_type "$2"
        fi
        ;;
    removeempty|rmempty)
        cmd_remove_empty
        ;;
    genrsa)
        cmd_genrsa
        ;;
    showrsa)
        cmd_showrsa
        ;;
    encssl)
        # For SSL only, still need to save database if not exists
        if [[ ! -f "$pathToFile" ]]; then
            saveDatabases
        fi
        crypto_type="ssl"
        enc_ssl
        ;;
    decssl)
        crypto_type="ssl"
        dec_ssl
        ;;
    encgpg)
        # For GPG only, still need to save database if not exists
        if [[ ! -f "$pathToFile" ]]; then
            saveDatabases
        fi
        crypto_type="gpg"
        enc_gpg
        ;;
    decgpg)
        crypto_type="gpg"
        dec_gpg
        ;;
    encaes)
        # For AES only, still need to save database if not exists
        if [[ ! -f "$pathToFile" ]]; then
            saveDatabases
        fi
        crypto_type="aes"
        enc_aes
        ;;
    decaes)
        crypto_type="aes"
        dec_aes
        ;;
    encrsa)
        # For RSA only, still need to save database if not exists
        if [[ ! -f "$pathToFile" ]]; then
            saveDatabases
        fi
        crypto_type="rsa"
        enc_rsa
        ;;
    decrsa)
        crypto_type="rsa"
        dec_rsa
        ;;
    encmd5)
        if [[ ! -f "$pathToFile" ]]; then
            echo "WARNING: No database found. Run 'encrypt' first for full encryption."
            saveDatabases
        fi
        encFile01
        encFolder01
        ;;
    decmd5)
        decFile01
        decFolder01
        ;;
    help|--help|-h)
        echo "Usage: $0 [command]"
        echo ""
        echo "  encrypt     - COMPLETE: Save database, content encrypt (using current type), THEN hash rename"
        echo "  decrypt     - COMPLETE: Hash restore names FIRST, THEN content decrypt (using current type)"
        echo "  settype     - Set crypto type: $0 settype [ssl|gpg|aes|rsa] (default: ssl)"
        echo "  removeempty - Remove all empty folders recursively in current directory"
        echo "  genrsa      - Generate new RSA key pair"
        echo "  showrsa     - Display RSA public key information"
        echo ""
        echo "  encssl      - ONLY encrypt file contents with SSL (creates .ssl files)"
        echo "  decssl      - ONLY decrypt .ssl files back to original"
        echo "  encgpg      - ONLY encrypt file contents with GPG (creates .gpg files)"
        echo "  decgpg      - ONLY decrypt .gpg files back to original"
        echo "  encaes      - ONLY encrypt file contents with AES-256-CBC (creates .aes files)"
        echo "  decaes      - ONLY decrypt .aes files back to original"
        echo "  encrsa      - ONLY encrypt file contents with RSA (creates .rsa files)"
        echo "  decrsa      - ONLY decrypt .rsa files back to original"
        echo "  encmd5      - ONLY rename files to $hash hashes"
        echo "  decmd5      - ONLY restore original filenames from $hash hashes"
        echo ""
        echo "Database location: $CONFIG_DIR"
        echo "Current hash algorithm: $hash"
        echo "Current crypto type: $crypto_type"
        ;;
    *)
        if [[ -z $1 ]]; then
            echo "No command specified. Use '$0 help' for usage information"
        else
            echo "Unknown command: $1"
            echo "Use '$0 help' for usage information"
        fi
        exit 1
        ;;
esac