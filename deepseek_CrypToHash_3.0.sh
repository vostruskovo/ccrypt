#!/bin/bash

# Configuration paths - stores database files for folder/file listings
# Use absolute paths that won't be affected by encryption
CONFIG_DIR="/etc/cryptoconfig"
pathToFolder="$CONFIG_DIR/folders.txt"
pathToFile="$CONFIG_DIR/files.txt"
pathToSsl="$CONFIG_DIR/ssl_pass.txt"  # Store SSL password hash
pathToGen="$CONFIG_DIR/gen.txt"
pathToEnc="$CONFIG_DIR/enc.txt"

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Global variables
pass=""        # Stores hashed password for hash-based renaming operations
ssl_pass_hash="" # Stores hashed SSL password for verification
hash="md5"     # Current hash algorithm being used (md5, sha1, sha256, sha512)
operation_mode="" # Track current operation mode

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

# Function to set password with hidden input
setPass() {
    local char
    local input_pass=""
    local purpose="$1"  # "hash" or "ssl"
    
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
        ssl_pass_plain="$input_pass"
        ssl_pass_hash=$(echo -n "$input_pass" | sha256sum | cut -d " " -f1)
        # Save SSL password hash for verification during decryption
        echo "$ssl_pass_hash" > "$pathToSsl"
    else
        # For hash-based renaming
        ssl_pass_plain=""  # Clear SSL password when setting hash password
        pass=$(echo -n "$input_pass" | ${hash}sum | cut -d " " -f1)
    fi
}

# Verify SSL password against stored hash
verify_ssl_pass() {
    if [[ ! -f "$pathToSsl" ]]; then
        echo "No SSL password record found. Did you encrypt with this tool?"
        return 1
    fi
    
    local stored_hash=$(cat "$pathToSsl")
    local input_hash=$(echo -n "$ssl_pass_plain" | sha256sum | cut -d " " -f1)
    
    if [[ "$input_hash" != "$stored_hash" ]]; then
        echo "Incorrect SSL password!"
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

# SSL Encryption
enc_ssl() {
    if [[ -z $ssl_pass_plain ]]; then
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
                if openssl enc -aes-${bits}-cbc -salt -in "$file" -out "${file}.ssl" -k "$ssl_pass_plain" 2>/dev/null; then
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
    if [[ -z $ssl_pass_plain ]]; then
        setPass "ssl" || return 1
    fi
    
    # Verify password against stored hash
    verify_ssl_pass || return 1
    
    local bits=256
    local tree=( $(find . -name "*.ssl" -type f 2>/dev/null | sed 's/^\.\///') )
    local decrypted_count=0
    
    echo "Found ${#tree[@]} SSL files to decrypt"
    
    for file in "${tree[@]}"; do
        local output="${file%.ssl}"
        echo "Decrypting: $file -> $output"
        if openssl enc -d -aes-256-cbc -in "$file" -out "$output" -k "$ssl_pass_plain" 2>/dev/null; then
            rm "$file"
            echo "  Decrypted: $file"
            ((decrypted_count++))
        else
            echo "  Failed to decrypt: $file (wrong password?)"
        fi
    done
    echo "SSL Decryption complete: $decrypted_count files decrypted"
}

# Hash-based Filename Encryption
encFile01() {
    if [[ -z $pass ]]; then
        setPass "hash" || return 1
    fi

    local tree=( $(find . -type f 2>/dev/null | grep -v "^\./$(basename "$CONFIG_DIR")" | sed 's/^\.\///') )
    local renamed_count=0
    
    for file in "${tree[@]}"; do
        local filename=$(getFile "$file")
        
        # Check if it's a .ssl file
        if [[ "$file" == *.ssl ]]; then
            local base="${filename%.ssl}"
            # Skip if already hashed
            if [[ $(isaEncOne ${base}) == 1 ]]; then
                continue
            fi
            local root=$(getROOT "$file")
            local C_base=$(encrypt "$base")
            echo "Renaming: $file -> $root/${C_base}.ssl"
            mv "$file" "$root/${C_base}.ssl" 2>/dev/null
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
        
        # Handle .ssl files
        local is_ssl=false
        local base_name="$current_name"
        if [[ "$current_name" == *.ssl ]]; then
            is_ssl=true
            base_name="${current_name%.ssl}"
        fi
        
        # Check if current name looks like a hash
        if [[ $(isaEncOne ${base_name}) == 1 ]]; then
            # Try to find matching original
            for original in "${allfiles[@]}"; do
                local orig_name=$(getFile "$original")
                local orig_path=$(getROOT "$original")
                local C_orig=$(encrypt "$orig_name")
                
                if [[ "$base_name" == "$C_orig" ]]; then
                    if [[ "$is_ssl" == true ]]; then
                        # For .ssl files, keep the .ssl extension
                        local target_name="${orig_name}.ssl"
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

# COMPLETE ENCRYPTION
encrypt_complete() {
    echo "=== COMPLETE ENCRYPTION PROCESS ==="
    echo "Step 1: Save database of original names"
    echo "--------------------------------------------------------"
    saveDatabases
    
    echo -e "\nStep 2: SSL Content Encryption"
    echo "--------------------------------------------------------"
    enc_ssl
    
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
    
    echo -e "\nStep 2: SSL Content Decryption"
    echo "--------------------------------------------------------"
    dec_ssl
    
    echo -e "\n=== DECRYPTION COMPLETE ==="
    echo "All files restored to original state"
}

# Main script execution
case "$1" in
    encrypt|main)
        encrypt_complete
        ;;
    decrypt|notmain)
        decrypt_complete
        ;;
    encssl)
        # For SSL only, still need to save database if not exists
        if [[ ! -f "$pathToFile" ]]; then
            saveDatabases
        fi
        enc_ssl
        ;;
    decssl)
        dec_ssl
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
        echo "Usage: $0 [encrypt|decrypt|encssl|decssl|encmd5|decmd5]"
        echo ""
        echo "  encrypt  - COMPLETE: Save database, SSL encrypt, THEN hash rename"
        echo "  decrypt  - COMPLETE: Hash restore names FIRST, THEN SSL decrypt"
        echo "  encssl   - ONLY encrypt file contents with SSL (creates .ssl files)"
        echo "  decssl   - ONLY decrypt .ssl files back to original"
        echo "  encmd5   - ONLY rename files to $hash hashes"
        echo "  decmd5   - ONLY restore original filenames from $hash hashes"
        echo ""
        echo "Database location: $CONFIG_DIR"
        echo "Current hash algorithm: $hash"
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