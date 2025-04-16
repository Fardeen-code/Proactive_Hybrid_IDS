function Invoke-IntrusionDetection {
    param([Parameter(ValueFromRemainingArguments=$true)]$params)
    
    # Get the directory where the script is located
    $scriptPath = "E:\network_ids"
    
    # Change to the script directory
    Push-Location $scriptPath
    
    try {
        # Execute the bash command with parameters
        & bash ./network_ids.sh $params
    }
    finally {
        # Return to the previous directory
        Pop-Location
    }
}

# Set the alias
Set-Alias -Name intrusion_detection -Value Invoke-IntrusionDetection

# Export the function and alias so they can be imported in other sessions
Export-ModuleMember -Function Invoke-IntrusionDetection -Alias intrusion_detection