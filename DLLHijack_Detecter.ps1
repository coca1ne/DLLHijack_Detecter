if($args.Count -le 0)
{
    Write-Host -foregroundColor Green "工具说明：`r`n    检测指定应用程序可能存在DLL劫持漏洞的DLL"
    Write-Host -foregroundColor Green "用法:`r`n    " $MyInvocation.MyCommand.Definition " c:\app.exe"
    return
}
Write-Host -foregroundColor Green "正在获取 KnownDLLs 注册表项..."
$RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
$DLLsList = (Get-ItemProperty $RegPath) | Get-Member | Select-Object -Property Name
[System.Collections.ArrayList]$KnownDLLsList = $DLLsList
$KnownDLLsList.Clear()
foreach($item in $DLLsList)
{
    if(($item.Name -ne "Equals") -and ($item.Name -ne "GetHashCode") -and ($item.Name -ne "GetType") -and ($item.Name -ne "ToString") -and 
    ($item.Name -ne "DllDirectory") -and ($item.Name -ne "DllDirectory32") -and ($item.Name -ne "PSChildName") -and ($item.Name -ne "PSDrive") -and 
    ($item.Name -ne "PSParentPath")  -and ($item.Name -ne "PSPath")  -and ($item.Name -ne "PSProvider"))
    {$KnownDLLsList.Add($item.Name.ToUpper()+".DLL") | Out-Null}
}
Write-Host -foregroundColor Green "获取 KnownDLLs 注册表项完毕！！！"

$FilePath = $args[0]
Write-Host -foregroundColor Green "正在启动宿主进程：" $args[0]
$process = [System.Diagnostics.Process]::Start($FilePath)
Write-Host -foregroundColor Green "正在获取宿主进程已加载的模块..."
sleep(1)
$modules = $process.Modules | Select-Object -Property ModuleName,FileName
Write-Host -foregroundColor Green "宿主进程已加载模块：[ "  $modules.Count " ]个"
kill $process.Id
$process.WaitForExit()
Write-Host -foregroundColor Green "宿主进程已结束！"
[System.Collections.ArrayList]$ModulesList = $modules
$ModulesList.RemoveAt(0)
Write-Host -foregroundColor Red "已检测到可能存在劫持漏洞的DLL："
foreach($module in $ModulesList)
{
    if(!$KnownDLLsList.Contains($module.ModuleName.ToUpper()))
    {
       "{0,-30}   {1,30}" -f $module.ModuleName, $module.FileName
    }
}
trap
{
    $info = $_.InvocationInfo
    Write-Host -foregroundColor Red "在第{" $info.ScriptLineNumber "}行，第{" $info.OffsetInLine "}列捕获到异常:"$_.Exception.Message
    return
}
