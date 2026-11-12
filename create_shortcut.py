import os
import subprocess

ps_script = """
$wsh = New-Object -ComObject WScript.Shell
$desktop = [System.Environment]::GetFolderPath('Desktop')
$shortcutPath = Join-Path $desktop "Natali Nails CRM.lnk"
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "C:\\Users\\bella\\Desktop\\App\\start_app.bat"
$shortcut.WorkingDirectory = "C:\\Users\\bella\\Desktop\\App"
$shortcut.IconLocation = "C:\\Users\\bella\\Desktop\\App\\static\\favicon.ico"
$shortcut.Description = "Кабінет Natali Nails Privé CRM"
$shortcut.Save()
"""

with open("temp_shortcut.ps1", "w", encoding="utf-8") as f:
    f.write(ps_script)

res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "temp_shortcut.ps1"], capture_output=True, text=True)
print(res.stdout)
if os.path.exists("temp_shortcut.ps1"):
    os.remove("temp_shortcut.ps1")
print("Shortcut created successfully on Desktop!")
