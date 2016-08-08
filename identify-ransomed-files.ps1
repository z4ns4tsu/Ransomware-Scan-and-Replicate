Param(
  [Parameter(Mandatory=$false)]
    [string] $SourceDir = $PWD,
  [Parameter(Mandatory=$false)]
    [string] $LogFile = ".\logfile.out"
)

Begin {
  function getShannonEntropy($file) {
    $fileEntropy = 0.0
    $byteCounts = @{}
    $byteTotal = 0
    
    # Folders don't really have entropy, so we'll skip calculating it for them.
    if(Test-Path $file -PathType Leaf) {
      $fileBytes = [System.IO.File]::ReadAllBytes($file)
      
      foreach ($fileByte in $fileBytes) {
          $byteCounts[$fileByte]++
          $byteTotal++
      }
  
      foreach($byte in 0..255) {
        $byteProb = ([double]$byteCounts[[byte]$byte])/$byteTotal
        if ($byteProb -gt 0) {
          $fileEntropy += (-1 * $byteProb) * [Math]::Log($byteProb, 2.0)
        }
      }
    }
    
    return $fileEntropy
  }
  
  function checkfile($FNAME) {
    # check file magic char for type - unknown file type has "data" as type
    $cmd = 'file'
    $args = @('-m', 'c:\utils\magic', $FNAME)
    $ftype = & $cmd $args
    
    $copy = 0
    if ($ftype -notmatch ".* data$") {
      $copy = 1
    } 
    else{
      # check on entropy. If less than 6, it's not encrypted well and is not compressed well, so it's likely data
      $entropy = getShannonEntropy($FNAME)
      if ($entropy -lt 6) {$copy = 1 }
    }
    
    Write-Verbose ("{0} - {1}" -f $entropy, $ftype)
    return $copy
  }

  Get-Date -Format "HH:mm:ss.ms" | Add-Content $LogFile
}

Process {
  $files = Get-ChildItem -recurse $SourceDir
  foreach ($file in $files) {
    # directories
    if (-not $file.psiscontainer) { 
      if (checkfile($file.fullname) -eq 1) { 
        # nothing to do here
        # maybe add to the logfile if a -v option is added
      }
      else { 
        ("{0} - SUSPECTED RANSOMWARE ENCRYPTED" -f $file.fullname) | Add-Content $LogFile
        Write-Output ("{0} - SUSPECTED RANSOMWARE ENCRYPTED" -f $file.fullname)
      }
    }
  }
}

End {
  Get-Date -Format "HH:mm:ss.ms" | Add-Content $LogFile
}