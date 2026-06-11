[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$In,[Parameter(Mandatory=$true)][string]$Out,[string]$K=$env:BUILD_BUNDLE_KEY)
$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($K)){throw 'Missing BUILD_BUNDLE_KEY.'}
if(-not(Test-Path -LiteralPath $In)){throw "Input not found: $In"}
function g([string]$s,[byte[]]$z){$r=[Security.Cryptography.Rfc2898DeriveBytes]::new($s,$z,200000,[Security.Cryptography.HashAlgorithmName]::SHA256);try{$m=$r.GetBytes(64);@{e=$m[0..31];h=$m[32..63]}}finally{$r.Dispose()}}
$m=[Text.Encoding]::ASCII.GetBytes('HDBUNDLE1')
$fs=[IO.File]::OpenRead((Resolve-Path -LiteralPath $In).Path)
try{
  if($fs.Length -lt ($m.Length+65)){throw 'Invalid input.'}
  $buf=New-Object byte[] $m.Length;$null=$fs.Read($buf,0,$buf.Length)
  for($i=0;$i -lt $m.Length;$i++){if($buf[$i] -ne $m[$i]){throw 'Invalid input.'}}
  $s=New-Object byte[] 16;$null=$fs.Read($s,0,16)
  $v=New-Object byte[] 16;$null=$fs.Read($v,0,16)
  $x=New-Object byte[] 32;$null=$fs.Read($x,0,32)
  $q=g $K $s
  $h=[Security.Cryptography.HMACSHA256]::new($q.h)
  try{
    foreach($part in @($m,$s,$v)){$null=$h.TransformBlock($part,0,$part.Length,$null,0)}
    $chunk=New-Object byte[] 1048576
    while(($read=$fs.Read($chunk,0,$chunk.Length)) -gt 0){$null=$h.TransformBlock($chunk,0,$read,$null,0)}
    $null=$h.TransformFinalBlock([byte[]]::new(0),0,0)
    $a=$h.Hash
  }finally{$h.Dispose()}
  $f=0;for($i=0;$i -lt $x.Length;$i++){$f=$f -bor ($x[$i] -bxor $a[$i])};if($f -ne 0){throw 'Input authentication failed.'}
  $dir=Split-Path -Parent $Out;if(-not[string]::IsNullOrWhiteSpace($dir)){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
  $fs.Position=$m.Length+16+16+32
  $aes=[Security.Cryptography.Aes]::Create()
  try{
    $aes.Mode=[Security.Cryptography.CipherMode]::CBC;$aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7;$aes.Key=$q.e;$aes.IV=$v
    $n=('Create'+'De'+'cryptor');$t=$aes.$n.Invoke()
    try{
      $outStream=[IO.File]::Open($Out,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
      try{
        $cs=[Security.Cryptography.CryptoStream]::new($outStream,$t,[Security.Cryptography.CryptoStreamMode]::Write)
        try{
          $chunk=New-Object byte[] 1048576
          while(($read=$fs.Read($chunk,0,$chunk.Length)) -gt 0){$cs.Write($chunk,0,$read)}
          $cs.FlushFinalBlock()
        }finally{$cs.Dispose()}
      }finally{$outStream.Dispose()}
    }finally{$t.Dispose()}
  }finally{$aes.Dispose()}
}finally{$fs.Dispose()}
Write-Host "Prepared $Out"
