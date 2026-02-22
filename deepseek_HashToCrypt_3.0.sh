#!/bin/bash

# Configuration paths
pathToFolder="/etc/configFolder_ccript.txt"
pathToFile="/etc/configFile_ccript.txt"
pathToSsl="/etc/configSsl_ccript.txt"
pathToGen="/etc/configSslGen_ccript.txt"
pathToEnc="/etc/configSslEnc_ccript.txt"

# Global variables
pass=""
ssl_pass=""
hash="sha512"
sizeHash=128  # Fixed: sha512 produces 128 chars, not dynamically calculated
cpt="ssl"  # Changed from .ssl to ssl for consistency
sizeOfCpt=${#cpt}

isaEncOne() {
    file=$1
    case ${hash} in
        "md5")
            [[ ${#file} -eq 32 ]] && echo 1 || echo 0
            ;;
        "sha1")
            [[ ${#file} -eq 40 ]] && echo 1 || echo 0
            ;;
        "sha256")
            [[ ${#file} -eq 64 ]] && echo 1 || echo 0
            ;;
        "sha512")
            [[ ${#file} -eq 128 ]] && echo 1 || echo 0
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
    printf "Enter password: "
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
    # Store BOTH the original password and hashed version
    ssl_pass="$input_pass"
    pass=$(echo -n "$input_pass" | ${hash}sum 2>/dev/null | cut -d " " -f1)
    return 0
}

# Helper functions
getHowmanySlashes() {
    echo "$1" | grep -o "/" | wc -l
}

getPath() {
    local howmanySlashes=$(getHowmanySlashes "$1")
    if [[ $howmanySlashes -eq 0 ]]; then
        echo "."
    else
        echo "$1" | cut -d "/" -f1-$((howmanySlashes + 1))
    fi
}

getPathFromFile() {
    local howmanySlashes=$(getHowmanySlashes "$1")
    if [[ -f "$1" ]]; then
        if [[ $howmanySlashes -eq 0 ]]; then
            echo "."
        else
            echo "$1" | cut -d "/" -f1-$((howmanySlashes))
        fi
    else
        if [[ $howmanySlashes -eq 0 ]]; then
            echo "."
        else
            echo "$1" | cut -d "/" -f1-$((howmanySlashes + 1))
        fi
    fi
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

getFolder() {
    local howmanySlashes=$(getHowmanySlashes "$1")
    if [[ $howmanySlashes -eq 0 ]]; then
        echo "$1"
    else
        echo "$1" | cut -d "/" -f$((howmanySlashes + 1))
    fi
}

validatin() {
    local file=$(getFile "$1")
    if [[ -n "$file" && "$file" != "." && "$file" != ".." ]]; then
        echo "true"
    else
        echo "false"
    fi
}

encrypt() {
    local file="$1"
    if [[ -z $pass ]]; then
        echo "Password not set" >&2
        return 1
    fi
    echo -n "$pass$file" | ${hash}sum 2>/dev/null | cut -d " " -f1
}

reverse() {
    local array=($*)
    local array_copy=()
    local x=$((${#array[@]} - 1))
    for i in $(seq $x -1 0); do  # Fixed: replaced eval with seq
        array_copy+=("${array[$i]}")
    done
    echo "${array_copy[@]}"
}

# Database maintenance functions
toFolder() {
    local path="$pathToFolder"
    # Skip current directory and parent directory
    local tree=( $(find . -type d ! -path "." ! -path ".." 2>/dev/null | sed 's/^\.\///') )
    
    # Clear the file and rewrite all folders
    > "$path" 2>/dev/null || { echo "Cannot write to $path"; return 1; }
    for item in "${tree[@]}"; do
        if [[ -n "$item" ]]; then
            echo "$item" >> "$path" 2>/dev/null
        fi
    done
}

toFile() {
    local path="$pathToFile"
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    
    # Clear the file and rewrite all files
    > "$path" 2>/dev/null || { echo "Cannot write to $path"; return 1; }
    for item in "${tree[@]}"; do
        if [[ -n "$item" ]]; then
            echo "$item" >> "$path" 2>/dev/null
        fi
    done
}

# File encryption/decryption (hash rename)
getAllEncFiles() {
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local E_files=()
    for item in "${tree[@]}"; do
        local file=$(getFile "$item")
        # Check if filename is a hash (correct length) and not a .ssl file
        if [[ $(isaEncOne "$file") -eq 1 && "$file" != *".ssl" ]]; then
            E_files+=("$item")
        fi
    done
    echo "${E_files[@]}"
}

getAllNoEncFiles() {
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local D_files=()
    for item in "${tree[@]}"; do
        local file=$(getFile "$item")
        # Files that are not hashes and not .ssl files
        if [[ $(isaEncOne "$file") -eq 0 && "$file" != *".ssl" ]]; then
            D_files+=("$item")
        fi
    done
    echo "${D_files[@]}"
}

encFile01() {
    if [[ -z $pass ]]; then
        echo "Enter password for file encryption:"
        setPass || return 1
    fi

    local files=($(getAllNoEncFiles))
    
    if [[ $# -gt 0 ]]; then
        # Encrypt specific files
        for target in "$@"; do
            # Remove leading ./ if present
            target="${target#./}"
            if [[ -f "$target" && "$target" != *".ssl" ]]; then
                local root=$(getROOT "$target")
                local file=$(getFile "$target")
                local C_file=$(encrypt "$file")
                echo "Renaming: $target -> $root/$C_file"
                mv -f "$target" "$root/$C_file"
            fi
        done
    else
        # Encrypt all unencrypted files
        for file in "${files[@]}"; do
            local root=$(getROOT "$file")
            local filename=$(getFile "$file")
            local C_file=$(encrypt "$filename")
            echo "Renaming: $file -> $root/$C_file"
            mv -f "$file" "$root/$C_file"
        done
    fi
}

decFile01() {
    if [[ -z $pass ]]; then
        echo "Enter password for file decryption:"
        setPass || return 1
    fi

    if [[ ! -f "$pathToFile" ]]; then
        echo "Database file not found: $pathToFile"
        return 1
    fi
    
    local allfiles=($(cat "$pathToFile"))
    local E_files=($(getAllEncFiles))
    
    if [[ $# -gt 0 ]]; then
        # Decrypt specific files
        for target in "$@"; do
            target="${target#./}"
            for enc_file in "${E_files[@]}"; do
                enc_file="${enc_file#./}"
                local enc_filename=$(getFile "$enc_file")
                local orig_filename=$(getFile "$target")
                local C_orig=$(encrypt "$orig_filename")
                
                if [[ "$enc_filename" == "$C_orig" ]]; then
                    local path=$(getPathFromFile "$enc_file")
                    echo "Restoring: $enc_file -> $path/$orig_filename"
                    mv -f "$enc_file" "$path/$orig_filename"
                    break
                fi
            done
        done
    else
        # Decrypt all encrypted files
        for ((i=${#E_files[@]}-1; i>=0; i--)); do
            for ((j=${#allfiles[@]}-1; j>=0; j--)); do
                local enc_filename=$(getFile "${E_files[$i]}")
                local orig_filename=$(getFile "${allfiles[$j]}")
                local C_orig=$(encrypt "$orig_filename")
                
                if [[ "$enc_filename" == "$C_orig" ]]; then
                    local path=$(getPathFromFile "${E_files[$i]}")
                    echo "Restoring: ${E_files[$i]} -> $path/$orig_filename"
                    mv -f "${E_files[$i]}" "$path/$orig_filename"
                    break
                fi
            done
        done
    fi
}

# Folder encryption/decryption (hash rename)
getAllEncFolders() {
    local tree=( $(find . -type d ! -path "." ! -path ".." 2>/dev/null | sed 's/^\.\///') )
    local E_folders=()
    for item in "${tree[@]}"; do
        local folder=$(getFile "$item")
        if [[ $(isaEncOne "$folder") -eq 1 ]]; then
            E_folders+=("$item")
        fi
    done
    echo "${E_folders[@]}"
}

getAllNoEncFolders() {
    local tree=( $(find . -type d ! -path "." ! -path ".." 2>/dev/null | sed 's/^\.\///') )
    local D_folders=()
    for item in "${tree[@]}"; do
        local folder=$(getFile "$item")
        if [[ $(isaEncOne "$folder") -eq 0 ]]; then
            D_folders+=("$item")
        fi
    done
    echo "${D_folders[@]}"
}

encFolder01() {
    if [[ -z $pass ]]; then
        echo "Enter password for folder encryption:"
        setPass || return 1
    fi

    local D_folders=($(getAllNoEncFolders))
    
    if [[ $# -gt 0 ]]; then
        # Encrypt specific folders
        for target in "$@"; do
            target="${target#./}"
            if [[ -d "$target" && "$target" != "." && "$target" != ".." ]]; then
                local howmanySlashes=$(getHowmanySlashes "$target")
                local path=$(echo "$target" | cut -d "/" -f1-$((howmanySlashes)))
                local folder=$(getFile "$target")
                local C_folder=$(encrypt "${folder}/")
                
                echo "Renaming: $target -> $path/$C_folder"
                mv -f "$target" "$path/$C_folder"
            fi
        done
    else
        # Encrypt all unencrypted folders (in reverse order for nested folders)
        for ((i=${#D_folders[@]}-1; i>=0; i--)); do
            local folder_item="${D_folders[$i]}"
            folder_item="${folder_item#./}"
            
            # Skip current directory
            if [[ "$folder_item" == "." || "$folder_item" == ".." ]]; then
                continue
            fi
            
            local root=$(getROOT "$folder_item")
            local folder=$(getFile "$folder_item")
            local answer=$(validatin "$folder_item")
            
            if [[ $answer == "false" ]]; then
                local C_folder=$(encrypt "${root}/")
                echo "Renaming: $folder_item -> $C_folder"
                mv -f "$folder_item" "$C_folder" 2>/dev/null
            else
                local C_folder=$(encrypt "${folder}/")
                echo "Renaming: $folder_item -> $root/$C_folder"
                mv -f "$folder_item" "$root/$C_folder" 2>/dev/null
            fi
        done
    fi
}

decFolder01() {
    if [[ -z $pass ]]; then
        echo "Enter password for folder decryption:"
        setPass || return 1
    fi

    if [[ ! -f "$pathToFolder" ]]; then
        echo "Database file not found: $pathToFolder"
        return 1
    fi

    local allfolders=($(cat "$pathToFolder"))
    local E_folders=($(getAllEncFolders))
    
    if [[ $# -gt 0 ]]; then
        # Decrypt specific folders
        for target in "$@"; do
            target="${target#./}"
            for enc_folder in "${E_folders[@]}"; do
                enc_folder="${enc_folder#./}"
                local enc_name=$(getFile "$enc_folder")
                local orig_name=$(getFile "$target")
                local C_orig=$(encrypt "${orig_name}/")
                
                if [[ "$enc_name" == "$C_orig" ]]; then
                    local path=$(getPathFromFile "$enc_folder")
                    echo "Restoring: $enc_folder -> $path/$orig_name"
                    mv -f "$enc_folder" "$path/$orig_name" 2>/dev/null
                    break
                fi
            done
        done
    else
        # Decrypt all encrypted folders
        for ((i=${#E_folders[@]}-1; i>=0; i--)); do
            for ((j=${#allfolders[@]}-1; j>=0; j--)); do
                local enc_name=$(getFile "${E_folders[$i]}")
                local orig_name=$(getFile "${allfolders[$j]}")
                local answer=$(validatin "${allfolders[$j]}")
                
                if [[ $answer == "false" ]]; then
                    local C_orig=$(encrypt "${allfolders[$j]}/")
                    if [[ "$C_orig" == "$enc_name" ]]; then
                        echo "Restoring: ${E_folders[$i]} -> ${allfolders[$j]}"
                        mv -f "${E_folders[$i]}" "${allfolders[$j]}" 2>/dev/null
                        break
                    fi
                else
                    local C_orig=$(encrypt "${orig_name}/")
                    if [[ "$C_orig" == "$enc_name" ]]; then
                        local path=$(getPathFromFile "${E_folders[$i]}")
                        echo "Restoring: ${E_folders[$i]} -> $path/${allfolders[$j]}"
                        mv -f "${E_folders[$i]}" "$path/${allfolders[$j]}" 2>/dev/null
                        break
                    fi
                fi
            done
        done
    fi
}

# SSL/OpenSSL functions
gen_ssl03() {
    local key=$(openssl rand -hex 64)
    echo "$key" >> "$pathToSsl" 2>/dev/null
    echo "$key"
}

gen_ssl02() {
    local bits=256
    local sslPass=$(openssl enc -aes-${bits}-cbc -k "$1" -P -md sha1 2>/dev/null | grep key | cut -d "=" -f2)
    echo "$sslPass" >> "$pathToGen" 2>/dev/null
    echo "$sslPass"
}

gen_ssl() {
    local bits=256
    local passSSL=$(echo "pass" | openssl enc -aes-256-ecb -e -a -K "$1" 2>/dev/null)
    echo "$passSSL" >> "$pathToEnc" 2>/dev/null
    echo "$passSSL"
}

enc_ssl() {
    if [[ -z $ssl_pass ]]; then
        echo "Enter password for SSL encryption:"
        setPass || return 1
    fi
    
    local bits=256
    # Find ALL files (including those in subdirectories)
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local files=()
    local encrypted_count=0
    
    for item in "${tree[@]}"; do
        # Skip .ssl files (already encrypted) and config files
        if [[ "$item" != *.ssl && "$item" != *"_ccript.txt" ]]; then
            files+=("$item")
        fi
    done
    
    echo "Found ${#files[@]} files to encrypt with SSL"
    
    if [[ ${#files[@]} -gt 0 ]]; then
        for file in "${files[@]}"; do
            if [[ -f "$file" ]]; then
                echo "SSL Encrypting: $file"
                # Create encrypted file with .ssl extension
                if openssl enc -aes-${bits}-cbc -salt -in "$file" -out "${file}.ssl" -k "$ssl_pass" 2>/dev/null; then
                    # Remove original file after successful encryption
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

dec_ssl() {
    if [[ -z $ssl_pass ]]; then
        echo "Enter password for SSL decryption:"
        setPass || return 1
    fi
    
    local bits=256
    # Find all .ssl files
    local tree=( $(find . -name "*.ssl" -type f 2>/dev/null | sed 's/^\.\///') )
    local decrypted_count=0
    
    echo "Found ${#tree[@]} SSL files to decrypt"
    
    if [[ $# -gt 0 ]]; then
        # Decrypt specific files
        for target in "$@"; do
            target="${target#./}"
            if [[ -f "$target" && "$target" == *.ssl ]]; then
                # Remove .ssl extension for output
                local output="${target%.ssl}"
                echo "Decrypting: $target -> $output"
                if openssl enc -d -aes-256-cbc -in "$target" -out "$output" -k "$ssl_pass" 2>/dev/null; then
                    rm "$target"
                    echo "  Decrypted: $target"
                    ((decrypted_count++))
                else
                    echo "  Failed to decrypt: $target (wrong password?)"
                fi
            fi
        done
    else
        # Decrypt all .ssl files
        for file in "${tree[@]}"; do
            local output="${file%.ssl}"
            echo "Decrypting: $file -> $output"
            if openssl enc -d -aes-256-cbc -in "$file" -out "$output" -k "$ssl_pass" 2>/dev/null; then
                rm "$file"
                echo "  Decrypted: $file"
                ((decrypted_count++))
            else
                echo "  Failed to decrypt: $file (wrong password?)"
            fi
        done
    fi
    echo "SSL Decryption complete: $decrypted_count files decrypted"
}

# Combined encryption function
encrypt_all() {
    echo "=== COMPLETE FILE ENCRYPTION (${hash^^} Rename + ${cpt^^}) ==="
    
    # Update databases
    toFile
    toFolder
    
    # Step 1: hash rename encryption
    echo -e "\n=== Step 1: ${hash} Rename Encryption ==="
    encFile01
    
    # Step 2: cpt content encryption
    echo -e "\n=== Step 2: ${cpt^^} Content Encryption ==="
    enc_ssl
    encFolder01
    echo -e "\n=== ENCRYPTION COMPLETE ==="
}

# Combined decryption function
decrypt_all() {
    echo "=== COMPLETE FILE DECRYPTION (${cpt^^} + ${hash} Rename) ==="
    
    # Step 1: cpt content decryption
    echo -e "\n=== Step 1: ${cpt^^} Content Decryption ==="
    dec_ssl
    
    # Update databases after cpt decryption
    toFile
    toFolder
    
    # Step 2: hash rename decryption
    echo -e "\n=== Step 2: ${hash} Rename Decryption ==="
    decFile01
    
    # Step 3: Folder hash rename decryption
    echo -e "\n=== Step 3: Folder ${hash} Rename Decryption ==="
    decFolder01
    
    echo -e "\n=== DECRYPTION COMPLETE ==="
}

# Main script execution
case "$1" in
    encrypt|main)
        encrypt_all
        ;;
    decrypt|notmain)
        decrypt_all
        ;;
    encfile)
        shift
        encFile01 "$@"
        ;;
    decfile)
        shift
        decFile01 "$@"
        ;;
    encfolder)
        shift
        encFolder01 "$@"
        ;;
    decfolder)
        shift
        decFolder01 "$@"
        ;;
    encssl)
        enc_ssl
        ;;
    decssl)
        dec_ssl
        ;;
    help|--help|-h)
        echo "Usage: $0 [encrypt|decrypt|encfile|decfile|encfolder|decfolder|encssl|decssl]"
        echo ""
        echo "  encrypt   - COMPLETE ENCRYPTION: ${hash^^} rename ALL files + ${cpt^^} encrypt ALL files"
        echo "  decrypt   - COMPLETE DECRYPTION: ${cpt^^} decrypt ALL files + ${hash^^} rename restore ALL files"
        echo "  encfile   - Encrypt specific files with ${hash^^} rename only (provide paths)"
        echo "  decfile   - Decrypt specific files from ${hash^^} rename only (provide paths)"
        echo "  encfolder - Encrypt specific folders with ${hash^^} rename only (provide paths)"
        echo "  decfolder - Decrypt specific folders from ${hash^^} rename only (provide paths)"
        echo "  encssl    - ${cpt^^} encrypt ALL files (content encryption)"
        echo "  decssl    - ${cpt^^} decrypt ALL .${cpt} files"
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