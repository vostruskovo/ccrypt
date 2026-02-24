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
        # Using -empty flag to find empty directories
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