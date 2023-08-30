#Generating a password for the user.

Function Generate-RandomPassword {
    param (
        [int]$Length = 12
    )

    $LowercaseChars = "abcdefghijklmnopqrstuvwxyz"
    $UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $NumberChars = "0123456789"
    $SymbolChars = "!@%*()_-+=?/"

    # Initialize with at least one character from each category
    $Password = $LowercaseChars[(Get-Random -Minimum 0 -Maximum $LowercaseChars.Length)]
    $Password += $UppercaseChars[(Get-Random -Minimum 0 -Maximum $UppercaseChars.Length)]
    $Password += $NumberChars[(Get-Random -Minimum 0 -Maximum $NumberChars.Length)]
    $Password += $SymbolChars[(Get-Random -Minimum 0 -Maximum $SymbolChars.Length)]

    # Calculate how many characters are left to reach the desired length
    $RemainingLength = $Length - 4

    # Combine all character sets
    $AllChars = $LowercaseChars + $UppercaseChars + $NumberChars + $SymbolChars

    # Add random characters from the combined set to fulfill the remaining length
    $Random = New-Object System.Random
    for ($i = 0; $i -lt $RemainingLength; $i++) {
        $RandomIndex = $Random.Next(0, $AllChars.Length)
        $Password += $AllChars[$RandomIndex]
    }

    # Shuffle the password characters
    $ShuffledChars = $Password.ToCharArray() | Get-Random -Count $Password.Length
    $Password = -join $ShuffledChars

    return $Password
}

$Password = Generate-RandomPassword -Length 12 -IncludeLowercase -IncludeUppercase -IncludeNumbers -IncludeSymbols