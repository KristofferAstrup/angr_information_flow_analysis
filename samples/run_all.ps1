$execfile = Resolve-Path -Path "./silent_execute.py"
Get-Childitem -Recurse -Path .\ -Filter *.py | % {cd $_.Directory; python $execfile $_.FullName}