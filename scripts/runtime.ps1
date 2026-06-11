[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$In,[Parameter(Mandatory=$true)][string]$Out,[string]$K=$env:BUILD_BUNDLE_KEY)
$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($K)){throw 'Missing BUILD_BUNDLE_KEY.'}
if(-not(Test-Path -LiteralPath $In)){throw "Input not found: $In"}
function g([string]$s,[byte[]]$z){$r=[Security.Cryptography.Rfc2898DeriveBytes]::new($s,$z,200000,[Security.Cryptography.HashAlgorithmName]::SHA256);try{$m=$r.GetBytes(64);@{e=$m[0..31];h=$m[32..63]}}finally{$r.Dispose()}}
$m=[Text.Encoding]::ASCII.GetBytes('HDBUNDLE1');$d=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $In).Path)
if($d.Length -lt ($m.Length+65)){throw 'Invalid input.'}
for($i=0;$i -lt $m.Length;$i++){if($d[$i] -ne $m[$i]){throw 'Invalid input.'}}
$o=$m.Length;$s=$d[$o..($o+15)];$o+=16;$v=$d[$o..($o+15)];$o+=16;$x=$d[$o..($o+31)];$o+=32;$c=$d[$o..($d.Length-1)]
$q=g $K $s;$b=New-Object byte[] ($m.Length+$s.Length+$v.Length+$c.Length);[Array]::Copy($m,0,$b,0,$m.Length);[Array]::Copy($s,0,$b,$m.Length,$s.Length);[Array]::Copy($v,0,$b,$m.Length+$s.Length,$v.Length);[Array]::Copy($c,0,$b,$m.Length+$s.Length+$v.Length,$c.Length)
$h=[Security.Cryptography.HMACSHA256]::new($q.h);try{$a=$h.ComputeHash($b)}finally{$h.Dispose()}
$f=0;for($i=0;$i -lt $x.Length;$i++){$f=$f -bor ($x[$i] -bxor $a[$i])};if($f -ne 0){throw 'Input authentication failed.'}
$n=('Create'+'De'+'cryptor');$p=[Security.Cryptography.Aes]::Create();try{$p.Mode=[Security.Cryptography.CipherMode]::CBC;$p.Padding=[Security.Cryptography.PaddingMode]::PKCS7;$p.Key=$q.e;$p.IV=$v;$t=$p.$n.Invoke();try{$r=$t.TransformFinalBlock($c,0,$c.Length)}finally{$t.Dispose()}}finally{$p.Dispose()}
$dir=Split-Path -Parent $Out;if(-not[string]::IsNullOrWhiteSpace($dir)){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
[IO.File]::WriteAllBytes($Out,$r);Write-Host "Prepared $Out"
