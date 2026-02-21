#!/bin/bash

# Configuration paths
pathToFolder="/etc/configFolder_ccript.txt"
pathToFile="/etc/configFile_ccript.txt"
pathToSsl="/etc/configSsl_ccript.txt"
pathToGen="/etc/configSslGen_ccript.txt"
pathToEnc="/etc/configSslEnc_ccript.txt"

# Global variables
pass=""
hash="sha512"
sizeHash=$(echo -n ${hash} | ${hash}sum | wc -c)
cpt=.ssl
sizeOfCpt=${#cpt}

#<<isaEncOne
isaEncOne() {
    file=$1
    case ${hash} in
        "md5")
        if [[ ${#1} -eq 32 ]]; then
            echo 1
        else
            echo 0
        fi
;;
        "sha1")
        [[ ${#1} -eq 40  ]] && echo 1 || echo 0 
;;
        "sha256")
        echo $(( ${#1} == 64 ? 1 : 0 ))
;;
        "sha512")
        if (( ${#1} == 128 )); then
            echo 1
        else
            echo 0
        fi        
;;
    esac

}
#isaEncOne


<<isaEncOne
isaEncOne() {
    case "$hash" in
        md5)
            if [[ ${#1} -eq 32 ]]; then
                echo 1
            else
                echo 0
            fi
            ;;
        sha1)
            if [[ ${#1} -eq 40 ]]; then
                echo 1
            else
                echo 0
            fi
            ;;
        sha256)
            if [[ ${#1} -eq 64 ]]; then
                echo 1
            else
                echo 0
            fi
            ;;
        sha512)
            if [[ ${#1} -eq 128 ]]; then
                echo 1
            else
                echo 0
            fi
            ;;
        *)
            echo 0
            ;;
    esac
}
isaEncOne
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
    pass=$(echo -n "$input_pass" | ${hash}sum | cut -d " " -f1)
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
    echo -n "$pass$file" | ${hash}sum | cut -d " " -f1
}

reverse() {
    local array=($*)
    local array_copy=()
    local x=$((${#array[@]} - 1))
    for i in $(eval echo {$x..0}); do
        array_copy+=("${array[$i]}")
    done
    echo "${array_copy[@]}"
}

# Database maintenance functions
toFolder() {
    local path="$pathToFolder"
    local tree=( $(find . -type d ! -path "." ! -path ".." 2>/dev/null | sed 's/^\.\///') )
    
    # Clear and rewrite the file
    > "$path"
    for item in "${tree[@]}"; do
        if [[ -n "$item" ]]; then
            echo "$item" >> "$path"
        fi
    done
}

toFile() {
    local path="$pathToFile"
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    
    # Clear and rewrite the file
    > "$path"
    for item in "${tree[@]}"; do
        if [[ -n "$item" ]]; then
            echo "$item" >> "$path"
        fi
    done
}

# SSL Encryption FIRST - encrypts ALL file contents
enc_ssl() {
    if [[ -z $ssl_pass ]]; then
        echo "Enter password for SSL encryption:"
        setPass || return 1
    fi
    
    local bits=256
    # Find ALL files that are not already .ssl files
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local files=()
    local encrypted_count=0
    
    for item in "${tree[@]}"; do
        if [[ "$item" != *.ssl ]]; then
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

# SSL Decryption
dec_ssl() {
    if [[ -z $ssl_pass ]]; then
        echo "Enter password for SSL decryption:"
        setPass || return 1
    fi
    
    local bits=256
    # Find all .ssl files recursively
    local ssl_files=( $(find . -name "*.ssl" -type f 2>/dev/null | sed 's/^\.\///') )
    local decrypted_count=0
    
    echo "Found ${#ssl_files[@]} SSL files to decrypt"
    
    if [[ ${#ssl_files[@]} -gt 0 ]]; then
        for file in "${ssl_files[@]}"; do
            local output="${file%.ssl}"
            echo "Decrypting: $file -> $output"
            if openssl enc -d -aes-${bits}-cbc -in "$file" -out "$output" -k "$ssl_pass" 2>/dev/null; then
                rm "$file"
                echo "  ✓ Decrypted: $file"
                ((decrypted_count++))
            else
                echo "  ✗ Failed to decrypt: $file (wrong password or corrupted file?)"
            fi
        done
        echo "SSL Decryption complete: $decrypted_count files decrypted"
    else
        echo "No .ssl files found to decrypt"
    fi
}

# hash Rename Encryption - renames files to MD5 hashes
encFile01() {
    if [[ -z $pass ]]; then
        echo "Enter password for ${hash} rename:"
        setPass || return 1
    fi

    # Find ALL files (including .ssl files now)
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local renamed_count=0
    
    for file in "${tree[@]}"; do
        local filename=$(getFile "$file")
        # Skip if already looks like an hash (x chars) and doesn't have extension issues
        if [[ ${#filename} -eq ${sizeHash} || ${#filename} -eq $((sizeHash + 4)) ]]; then # x chars for .ssl files (x + 4)
            continue
        fi
        
        local root=$(getROOT "$file")
        local C_name=$(encrypt "$filename")
        
        # If it's a .ssl file, we want to keep the .ssl extension but rename the base
        if [[ "$filename" == *.ssl ]]; then
            
            local C_base=$(encrypt "$filename")
            echo "Renaming: $root/$filename -> $root/$C_base"
            mv "$root/$filename" "$root/$C_base" 2>/dev/null
            ((renamed_count++))
        else
            echo "Renaming: $root/$filename -> $root/$C_name"
            mv "$root/$filename" "$root/$C_name" 2>/dev/null
            ((renamed_count++))
        fi
    done
    echo "MD5 Rename complete: $renamed_count files renamed"
}

# MD5 Rename Decryption - restores original names
decFile01() {
    if [[ -z $pass ]]; then
        echo "Enter password for ${hash} rename restoration:"
        setPass || return 1
    fi

    if [[ ! -f "$pathToFile" ]]; then
        echo "Database file not found: $pathToFile"
        return 1
    fi
    
    local allfiles=($(cat "$pathToFile"))
    # Find all files recursively, excluding directories
    local tree=( $(find . -type f 2>/dev/null | sed 's/^\.\///') )
    local restored_count=0
    
    echo "Found ${#tree[@]} files to process for name restoration"
    
    for current_file in "${tree[@]}"; do
        local current_name=$(getFile "$current_file")
        local current_path=$(getROOT "$current_file")
        
        # Handle .ssl files specially
        local is_ssl=false
        local base_name="$current_name"
        if [[ "$current_name" == *.ssl ]]; then
            is_ssl=true
            base_name="${current_name%.ssl}"
        fi
        
        # Check if current name looks like a hash (x chars)
        if [[ ${#base_name} -eq ${sizeHash} ]]; then
            # Try to find matching original
            for original in "${allfiles[@]}"; do
                local orig_name=$(getFile "$original")
                local C_orig=$(encrypt "$orig_name")
                
                if [[ "$base_name" == "$C_orig" ]]; then
                    local orig_path=$(getROOT "$original")
                    # Create destination directory if it doesn't exist
                    if [[ "$orig_path" != "." ]]; then
                        mkdir -p "$orig_path" 2>/dev/null
                    fi
                    
                    if [[ "$is_ssl" == true ]]; then
                        echo "Restoring: $current_file -> $orig_path/${orig_name}.ssl"
                        mv "$current_file" "$orig_path/${orig_name}.ssl" 2>/dev/null
                    else
                        echo "Restoring: $current_file -> $orig_path/$orig_name"
                        mv "$current_file" "$orig_path/$orig_name" 2>/dev/null
                    fi
                    ((restored_count++))
                    break
                fi
            done
        fi
    done
    echo "${hash} Rename restoration complete: $restored_count files restored"
}

# Folder encryption (rename to hash)
encFolder01() {
    if [[ -z $pass ]]; then
        echo "Enter password for folder encryption:"
        setPass || return 1
    fi

    # Get all directories (deepest first)
    local tree=( $(find . -type d ! -path "." ! -path ".." 2>/dev/null | sed 's/^\.\///' | awk '{print length, $0}' | sort -nr | cut -d' ' -f2-) )
    
    for folder_item in "${tree[@]}"; do
        local folder=$(getFile "$folder_item")
        
        # Skip if already  hash (x chars)
        if [[ ${#folder} -eq ${sizeHash} ]]; then
            continue
        fi
        
        local root=$(getROOT "$folder_item")
        local C_folder=$(encrypt "${folder}/")
        
        echo "Renaming folder: $root/$folder -> $root/$C_folder"
        mv "$root/$folder" "$root/$C_folder" 2>/dev/null
    done
}

# Folder decryption
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
    # Get all directories (deepest first for proper hierarchy)
    local tree=( $(find . -type d ! -path "." ! -path ".." 2>/dev/null | sed 's/^\.\///' | awk '{print length, $0}' | sort -nr | cut -d' ' -f2-) )
    local restored_count=0
    
    echo "Found ${#tree[@]} folders to process for name restoration"
    
    for current_folder in "${tree[@]}"; do
        local current_name=$(getFile "$current_folder")
        
        # Check if current name looks like a hash (x chars)
        if [[ ${#current_name} -eq ${sizeHash} ]]; then
            # Try to find matching original
            for original in "${allfolders[@]}"; do
                local orig_name=$(getFile "$original")
                local C_orig=$(encrypt "${orig_name}/")
                
                if [[ "$current_name" == "$C_orig" ]]; then
                    local current_path=$(getROOT "$current_folder")
                    local orig_path=$(getROOT "$original")
                    
                    echo "Restoring folder: $current_path/current_name -> $orig_path/$orig_name"
                    mv "$current_path/current_name" "$orig_path/$orig_name" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        ((restored_count++))
                    fi
                    break
                fi
            done
        fi
    done
    echo "Folder restoration complete: $restored_count folders restored"
}

# NEW: Complete encryption function (cpt FIRST, THEN hash rename)

encrypt_complete() {
    echo ${cpt^^} \& ${hash^^}
    echo "=== COMPLETE ENCRYPTION PROCESS ==="
    echo "Step 1: ${cpt%.*} Content Encryption (encrypts all file contents)"
    echo "--------------------------------------------------------"
    enc_ssl

    echo -e "\nStep 2: Update databases with new ${cpt} files"
    echo "--------------------------------------------------------"
    toFile
    toFolder
    
    echo -e "\nStep 3: ${hash} Filename Encryption (renames all files to ${hash} hashes)"
    echo "--------------------------------------------------------"
    encFile01
    encFolder01
    
    echo -e "\n=== ENCRYPTION COMPLETE ==="
    echo "All files are now:"
    echo "  1. Content encrypted with ${cpt^^} (${cpt} files)"
    echo "  2. Filenames renamed to ${hash} hashes"
}

# NEW: Complete decryption function (hash rename restore FIRST, THEN cpt decrypt)
decrypt_complete() {
    echo "=== COMPLETE DECRYPTION PROCESS ==="
    echo "Step 1: ${hash} Filename Restoration (restores original filenames)"
    echo "--------------------------------------------------------"
    decFolder01
    #decFile01
    
    echo -e "\nStep 2: ${cpt^^} Content Decryption (decrypts all ${cpt} file contents)"
    echo "--------------------------------------------------------"
    dec_ssl
    
    echo -e "\n=== DECRYPTION COMPLETE ==="
    echo "All files restored to original state"
}

$*
<<cases
# Main script execution
case "$1" in
    encOne)
    isaEncOne 
    ;;
    encrypt|main)
        encrypt_complete
        ;;
    decrypt|notmain)
        decrypt_complete
        ;;
    encssl)
        enc_ssl
        ;;
    decssl)
        dec_ssl
        ;;
    encmd5)
        shift
        encFile01
        encFolder01
        ;;
    decmd5)
        shift
        decFile01
        decFolder01
        ;;
    help|--help|-h)
        echo "Usage: $0 [encrypt|decrypt|encssl|decssl|encmd5|decmd5]"
        echo ""
        echo "  encrypt  - COMPLETE: SSL encrypt ALL files, THEN rename to MD5 hashes"
        echo "  decrypt  - COMPLETE: Restore MD5 names FIRST, THEN SSL decrypt ALL files"
        echo "  encssl   - ONLY encrypt file contents with SSL (creates .ssl files)"
        echo "  decssl   - ONLY decrypt .ssl files back to original"
        echo "  encmd5   - ONLY rename files to MD5 hashes (assumes already SSL encrypted)"
        echo "  decmd5   - ONLY restore original filenames from MD5 hashes"
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

cases