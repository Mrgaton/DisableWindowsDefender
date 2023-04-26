using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace DisableWindowsDefender
{
    internal class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            //Console.WriteLine(Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Add-Type -TypeDefinition 'using System;\r\nusing System.Runtime.InteropServices;\r\n \r\nnamespace Utilities {\r\n   public static class Display\r\n   {\r\n      [DllImport(\"user32.dll\", CharSet = CharSet.Auto)]\r\n      private static extern IntPtr SendMessage(\r\n         IntPtr hWnd,\r\n         UInt32 Msg,\r\n         IntPtr wParam,\r\n         IntPtr lParam\r\n      );\r\n \r\n      public static void PowerOff ()\r\n      {\r\n         SendMessage(\r\n            (IntPtr)0xffff, // HWND_BROADCAST\r\n            0x0112,         // WM_SYSCOMMAND\r\n            (IntPtr)0xf170, // SC_MONITORPOWER\r\n            (IntPtr)0x0002  // POWER_OFF\r\n         );\r\n      }\r\n   }\r\n}'\r\n[Utilities.Display]::PowerOff()")));

            /*  Console.WriteLine(Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("$c2F4=2;$cnV=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);if($cnV){$b2Fu=(Get-Item .).FullName;$eHVt=1;Add-MpPreference -ExclusionPath $env:TEMP};Start-Sleep -Seconds(Get-Random -Min $eHVt -Max $c2F4);$bW8A=Get-CimInstance -ClassName Win32_OperatingSystem|Select LastBootUpTime")));
               Console.ReadKey();*/

            ChangeConsoleColor(ConsoleColor.DarkMagenta);
            Console.WriteLine("Espere mientras cargamos algunas variables de entorno");
            Console.WriteLine();
            ChangeConsoleColor(ConsoleColor.Magenta);
            Console.WriteLine("Informacion del Dispositivo");
            ChangeConsoleColor(ConsoleColor.Yellow);

            bool ProtecionContraAlteraciones = false;
            try
            {
                bool DataExecutionPrevention = WindowsDefender.DefenderGetConfig.IsDataExecutionPreventionEnabled();
                Console.WriteLine("Prevención de ejecución de datos: " + DataExecutionPrevention.ToString());

                bool TpmEnabled = WindowsDefender.DefenderGetConfig.IsTpmEnabled();
                Console.WriteLine("Tpm activado: " + TpmEnabled.ToString());

                bool SecureBoot = WindowsDefender.DefenderGetConfig.IsSecureBootEnabled();
                Console.WriteLine("Arranque segurro: " + SecureBoot.ToString());

                ChangeConsoleColor(ConsoleColor.Magenta);
                Console.WriteLine();
                Console.WriteLine("Informacion del Windows defender");
                ChangeConsoleColor(ConsoleColor.Yellow);

                bool DefenderDisabled = WindowsDefender.DefenderGetConfig.IsDefenderDissabled();
                Console.WriteLine("Defender ejecutandose: " + WindowsDefender.DefenderGetConfig.IsDefenderRunning());
                Console.WriteLine("Defender desabilitado: " + DefenderDisabled);
                Console.WriteLine();

                bool ProtecionEnTIempoReal = WindowsDefender.DefenderGetConfig.IsRealtimeProtectionEnabled();
                Console.WriteLine("Protecion en tiempo real: " + ProtecionEnTIempoReal);

                bool ProtecionBasadaEnNuve = WindowsDefender.DefenderGetConfig.IsMAPSReportingEnabled();
                Console.WriteLine("Protecion basada en la nuve: " + ProtecionBasadaEnNuve);

                bool EnvioDeMuestrasAutomatico = WindowsDefender.DefenderGetConfig.IsSubmintSamplesConsentEnabled();
                Console.WriteLine("Envio de muestras automatica: " + EnvioDeMuestrasAutomatico);

                ProtecionContraAlteraciones = WindowsDefender.DefenderGetConfig.IsTamperProtectionEnabled();
                Console.WriteLine("Protecion contra alteraciones: " + ProtecionContraAlteraciones);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString(), ConsoleColor.Red);
            }
            Console.WriteLine();

            if (QuestionTrueFalse("Quieres desactivar el windows defender?"))
            {
                if (ProtecionContraAlteraciones)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine();
                    Console.WriteLine("Error desabilita la protecion contra alteraciones antes de desativar el windows defender");
                    Console.ReadLine();
                    Environment.Exit(1);
                }

                Console.WriteLine();
                Console.WriteLine("Desactivando defender");
                WindowsDefender.DisableWindowsDefender();
                Console.WriteLine("");
                Console.WriteLine("Windows defender desactivado");
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("Activando defender");
                WindowsDefender.EnableWindowsDefender();
                Console.WriteLine("");
                Console.WriteLine("Windows defender activado");
            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Si el windows defender hace cosas raras prueba a ejecutar el comando sfc /scannow y reiniciar el equipo");

            Console.ReadKey();
        }

        public static bool QuestionTrueFalse(string QuestionText)
        {
            ChangeConsoleColor(ConsoleColor.Cyan);
            Console.Write(QuestionText + " [");
            ChangeConsoleColor(ConsoleColor.Red);
            Console.Write("S");
            ChangeConsoleColor(ConsoleColor.Cyan);
            Console.Write(",");
            ChangeConsoleColor(ConsoleColor.Red);
            Console.Write("N");
            ChangeConsoleColor(ConsoleColor.Cyan);
            Console.Write("]?");

            ChangeConsoleColor(Console.BackgroundColor);
            ConsoleKeyInfo Chares = Console.ReadKey();

            Console.Write("\b");
            Console.Write("\n");

            Console.ForegroundColor = ConsoleColor.White;

            if (Chares.KeyChar.ToString().ToLower() == "t" | Chares.KeyChar.ToString().ToLower() == "y" | Chares.KeyChar.ToString().ToLower() == "s")
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private static void ChangeConsoleColor(ConsoleColor color)
        {
            Console.ForegroundColor = color;
        }

        public class WindowsDefender
        {
            private WindowsDefender()
            {
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows\System", "DisableCMD", "0", RegistryValueKind.DWord);
            }

            public static void DisableWindowsDefender()
            {
                KillProcess("smartscreen");
                DefenderSetConfig.DisableSmartScreen();
                DisableAutoRunRegedit("SecurityHealth");

                RunPowerShellCommand("Set-MpPreference -DisableIOAVProtection $true");
                RunPowerShellCommand("Set-MpPreference -DisableRealtimeMonitoring $true");
                RunPowerShellCommand("Set-MpPreference -DisableBehaviorMonitoring $true");
                RunPowerShellCommand("Set-MpPreference -DisableBlockAtFirstSeen $true");
                RunPowerShellCommand("Set-MpPreference -DisableIOAVProtection $true");
                RunPowerShellCommand("Set-MpPreference -DisablePrivacyMode $true");
                RunPowerShellCommand("Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true");
                RunPowerShellCommand("Set-MpPreference -DisableArchiveScanning $true");
                RunPowerShellCommand("Set-MpPreference -DisableIntrusionPreventionSystem $true");
                RunPowerShellCommand("Set-MpPreference -DisableScriptScanning $true");
                RunPowerShellCommand("Set-MpPreference -SubmitSamplesConsent 2");
                RunPowerShellCommand("Set-MpPreference -MAPSReporting 0");
                RunPowerShellCommand("Set-MpPreference -HighThreatDefaultAction 6 -Force");
                RunPowerShellCommand("Set-MpPreference -ModerateThreatDefaultAction 6");
                RunPowerShellCommand("Set-MpPreference -LowThreatDefaultAction 6");
                RunPowerShellCommand("Set-MpPreference -SevereThreatDefaultAction 6");
                RunPowerShellCommand("netsh advfirewall set allprofiles state off");

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "EnableFirewall", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", "0", RegistryValueKind.DWord);

                WriteRegristyKey(@Registry.LocalMachine,@"Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "EnableFirewall", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "DisableAntiVirus", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "ServiceKeepAlive", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "AllowFastService", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "DisableRoutinelyTakingAction", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "HideExclusionsFromLocalAdmins", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "ServiceKeepAlive", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "AllowFastService", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender", "AllowFastServiceStartup", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Features");
                WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Features", "DeviceControlEnabled", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\MpEngine");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\MpEngine", "MpEnablePus", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\MpEngine", "DisableGradualRelease", "1", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRoutinelyTakingAction", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScanOnRealtimeEnable", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScriptScanning", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRawWriteNotification", "1", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\UX Configuration");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\UX Configuration", "Notification_Suppress", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\UX Configuration", "SuppressRebootNotification", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\UX Configuration", "UILockdown", "1", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Reportin");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Reportin", "DisableEnhancedNotifications", "1", RegistryValueKind.DWord);

                RunProcess(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\Windows Defender\MpCmdRun.exe", "-RemoveDefinitions -All");

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet", "DisableBlockAtFirstSeen", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet", "SpynetReporting", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet", "SubmitSamplesConsent", "2", RegistryValueKind.DWord);

                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", "0", RegistryValueKind.DWord);

                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Disable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance\" /Disable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Disable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Disable");

                CloseDefenderSettings();

                string DefenderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).ToString(), @"Microsoft\Windows Defender");

                if (Directory.Exists(DefenderPath))
                {
                    string DefenderScansPath = Path.Combine(DefenderPath, @"Scans");

                    string EngineDatabase = Path.Combine(DefenderScansPath, "mpenginedb.db");
                    if (File.Exists(EngineDatabase))
                    {
                        File.Delete(EngineDatabase);
                    }

                    string ProtectionHystoryPath = Path.Combine(DefenderScansPath, @"History");
                    if (Directory.Exists(ProtectionHystoryPath))
                    {
                        DeleteDir(ProtectionHystoryPath);
                    }
                }
            }

            public static void EnableWindowsDefender()
            {
                DefenderSetConfig.EnableSmartScreen();
                AcceptAutoRunRegedit("SecurityHealth");

                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender");
                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\MpEngine");
                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection");
                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Reportin");
                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet");
                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\UX Configuration");

                RunPowerShellCommand("Set-MpPreference -DisableIOAVProtection $false");
                RunPowerShellCommand("Set-MpPreference -DisableRealtimeMonitoring $false");
                RunPowerShellCommand("Set-MpPreference -DisableBehaviorMonitoring $false");
                RunPowerShellCommand("Set-MpPreference -DisableBlockAtFirstSeen $false");
                RunPowerShellCommand("Set-MpPreference -DisableIOAVProtection $false");
                RunPowerShellCommand("Set-MpPreference -DisablePrivacyMode $false");
                RunPowerShellCommand("Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false");
                RunPowerShellCommand("Set-MpPreference -DisableArchiveScanning $false");
                RunPowerShellCommand("Set-MpPreference -DisableIntrusionPreventionSystem $false");
                RunPowerShellCommand("Set-MpPreference -DisableScriptScanning $false");
                RunPowerShellCommand("Set-MpPreference -SubmitSamplesConsent 1");
                RunPowerShellCommand("Set-MpPreference -MAPSReporting 2");

                try
                {
                    GetPermissionsOnRegristyKey(@"MACHINE\SOFTWARE\Microsoft\Windows Defender\Features");
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", "5", RegistryValueKind.DWord);
                }
                catch { }

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "DisableNotifications", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "DisableNotifications", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "EnableFirewall", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "DisableNotifications", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", "1", RegistryValueKind.DWord);

                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall");
                RunPowerShellCommand("netsh advfirewall set allprofiles state on");

                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Enable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance\" /Enable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Enable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Enable");
                RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Enable");

                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", "1", RegistryValueKind.DWord);

                RunProcess(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\Windows Defender\MpCmdRun.exe", "-SignatureUpdate");

                CloseDefenderSettings();

                Console.ReadLine();
            }

            public static void CloseDefenderSettings()
            {
                foreach (Process Proc in Process.GetProcesses())
                {
                    try
                    {
                        if (Proc.ProcessName == "SecHealthUI")
                        {
                            Proc.Kill();
                        }
                    }
                    catch { }
                }
            }

            private static void DeleteDir(string Path)
            {
                DirectoryInfo Dir = new DirectoryInfo(Path);

                foreach (FileInfo File in Dir.GetFiles())
                {
                    try
                    {
                        File.Delete();
                    }
                    catch { }
                }

                foreach (DirectoryInfo SubDir in Dir.GetDirectories())
                {
                    try
                    {
                        SubDir.Delete(true);
                    }
                    catch
                    {
                        try
                        {
                            DeleteDir(SubDir.FullName);
                        }
                        catch { }
                    }
                }
            }

            public static void WriteRegristyKey(RegistryKey Hive, string Key, string Name, dynamic Data, RegistryValueKind Kind)
            {
                try
                {
                    Hive.OpenSubKey(Key, true).SetValue(Name, Data, Kind);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error writing on " + Hive + "\\" + Key + "\n" + ex.ToString());
                }
            }

            private static void CreateRegristyFolder(RegistryKey Hive, string Key)
            {
                try
                {
                    Hive.CreateSubKey(Key);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error creating folder on " + Hive + "\\" + Key + "\n" + ex.ToString());
                }
            }

            private static void DeleteRegristyFolderTree(RegistryKey Hive, string Key)
            {
                try
                {
                    RegistryKey Fonder = Hive.OpenSubKey(Key, true);

                    if (Fonder != null)
                    {
                        foreach (string Value in Fonder.GetValueNames())
                        {
                            try
                            {
                                Fonder.DeleteValue(Value);
                            }
                            catch { }
                        }
                    }

                    Registry.LocalMachine.DeleteSubKeyTree(Key, false);
                }
                catch (UnauthorizedAccessException) {  }
                catch (Exception ex)
                {
                    Console.WriteLine("Error deleting fonder " + Hive + "\\" + Key + "\n" + ex.ToString());
                }
            }

            public static bool GetPermissionsOnRegristyKey(string name)
            {
                try
                {
                    SID_IDENTIFIER_AUTHORITY sidNTAuthority = SECURITY_NT_AUTHORITY;
                    IntPtr sidAdmin = IntPtr.Zero;
                    AllocateAndInitializeSid(ref sidNTAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, ref sidAdmin);

                    EXPLICIT_ACCESS[] explicitAccesss = new EXPLICIT_ACCESS[1];
                    explicitAccesss[0].grfAccessPermissions = ACCESS_MASK.GENERIC_ALL;
                    explicitAccesss[0].grfAccessMode = ACCESS_MODE.SET_ACCESS;
                    explicitAccesss[0].grfInheritance = NO_INHERITANCE;
                    explicitAccesss[0].Trustee.TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;
                    explicitAccesss[0].Trustee.TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_GROUP;
                    explicitAccesss[0].Trustee.ptstrName = sidAdmin;

                    IntPtr acl = IntPtr.Zero;
                    SetEntriesInAcl(1, ref explicitAccesss[0], (IntPtr)0, ref acl);

                    Action<string, bool> setPrivilege = (privilege, allow) =>
                    {
                        IntPtr token = IntPtr.Zero;
                        TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES();
                        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token);

                        if (allow)
                        {
                            LUID luid;
                            LookupPrivilegeValueA(null, privilege, out luid);
                            tokenPrivileges.PrivilegeCount = 1;
                            tokenPrivileges.Privileges = new LUID_AND_ATTRIBUTES[1];
                            tokenPrivileges.Privileges[0].Luid = luid;
                            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                        }

                        AdjustTokenPrivileges(token, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
                        CloseHandle(token);
                    };
                    setPrivilege(SE_TAKE_OWNERSHIP_NAME, true);

                    SetNamedSecurityInfo(name, WindowsDefender.SE_OBJECT_TYPE.SE_REGISTRY_KEY, SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION, sidAdmin, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    setPrivilege(SE_TAKE_OWNERSHIP_NAME, false);
                    SetNamedSecurityInfo(name, WindowsDefender.SE_OBJECT_TYPE.SE_REGISTRY_KEY, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);

                    FreeSid(sidAdmin);
                    LocalFree(acl);
                }
                catch
                {
                    return false;
                }

                return true;
            }

            private static void KillProcess(string Processname)
            {
                foreach (Process Proc in Process.GetProcessesByName(Processname))
                {
                    try
                    {
                        Proc.Kill();
                    }
                    catch
                    {
                    }
                }
            }

            private static void AcceptAutoRunRegedit(string AplicationRegeditName)
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", AplicationRegeditName, new byte[] { 0002, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00 }, RegistryValueKind.Binary);
            }

            private static void DisableAutoRunRegedit(string AplicationRegeditName)
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", AplicationRegeditName, new byte[] { 0099, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99 }, RegistryValueKind.Binary);
            }

            private static string RunPowerShellCommand(string Command)
            {
                return RunProcess(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"), "-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand \"" + Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(Command)) + "\"");
            }

            private static string RunCmdCommand(string Command)
            {
                return RunProcess(Path.Combine(Environment.SystemDirectory, "Cmd.exe"), "/d /q /c " + Command);
            }
            private static string RunProcess(string FilePath, string FileArguments)
            {
                try
                {
                    Process ComandoAEjecutar = new Process();
                    ComandoAEjecutar.StartInfo.FileName = FilePath;
                    ComandoAEjecutar.StartInfo.Arguments = FileArguments;
                    ComandoAEjecutar.StartInfo.UseShellExecute = false;
                    ComandoAEjecutar.StartInfo.RedirectStandardOutput = true;
                    ComandoAEjecutar.StartInfo.RedirectStandardError = true;
                    ComandoAEjecutar.Start();
                    string OutputDelComando = ComandoAEjecutar.StandardOutput.ReadToEnd();

                    return OutputDelComando;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }

                return null;
            }

            public static void AddExclusionPath(string Pathe)
            {
                if (Pathe.EndsWith("\\"))
                {
                    Pathe = Pathe.Remove(Pathe.Length - 1);
                }

                RunPowerShellCommand("Add-MpPreference -ExclusionPath '" + Pathe + "'");
            }

            public static void AddExclusionExtension(string Extension)
            {
                RunPowerShellCommand("Add-MpPreference -ExclusionExtension '" + Extension + "'");
            }

            public static void AddExclusionProcess(string ProcessName)
            {
                RunPowerShellCommand("Add-MpPreference -ExclusionProcess '" + ProcessName + "'");
            }

            public static class DefenderGetConfig
            {
                public static ServiceController GetWIndowsDefenderService()
                {
                    return new ServiceController("WinDefend");
                }

                public static bool IsDefenderInstalled()
                {
                    try
                    {
                        GetWIndowsDefenderService();
                    }
                    catch
                    {
                        return false;
                    }

                    return true;
                }

                public static bool IsDefenderRunning()
                {
                    try
                    {
                        return GetWIndowsDefenderService().Status == ServiceControllerStatus.Running;
                    }
                    catch { }

                    return false;
                }

                public static bool IsDefenderDissabled()
                {
                    try
                    {
                        return GetWIndowsDefenderService().StartType != ServiceStartMode.Automatic;
                    }
                    catch { }

                    return false;
                }

                public static bool IsRealtimeProtectionEnabled()
                {
                    string OutputCommand = RunPowerShellCommand("Get-MpPreference | select DisableRealtimeMonitoring").ToLower();

                    if (OutputCommand.Contains("true"))
                    {
                        return false;
                    }
                    return true;
                }

                public static bool IsMAPSReportingEnabled()
                {
                    string OutputCommand = RunPowerShellCommand("Get-MpPreference | select MAPSReporting").ToLower();

                    if (OutputCommand.Contains("0"))
                    {
                        return false;
                    }
                    return true;
                }

                public static bool IsSubmintSamplesConsentEnabled()
                {
                    string OutputCommand = RunPowerShellCommand("Get-MpPreference | select SubmitSamplesConsent").ToLower();

                    if (OutputCommand.Contains("0") | OutputCommand.Contains("2"))
                    {
                        return false;
                    }
                    return true;
                }

                public static bool IsTamperProtectionEnabled()
                {
                    string OutputCommand = RunPowerShellCommand("Get-MpComputerStatus | select IsTamperProtected").ToLower();

                    if (OutputCommand.Contains("true"))
                    {
                        return true;
                    }
                    return false;
                }

                public static bool IsDataExecutionPreventionEnabled()
                {
                    return RunCmdCommand("wmic OS Get DataExecutionPrevention_SupportPolicy").Split('\n')[1].Trim() != "0";
                }

                public static bool IsTpmEnabled()
                {
                    string Info = RunCmdCommand(@"wmic /namespace:\\root\cimv2\security\microsofttpm path win32_tpm get IsEnabled_InitialValue").Split('\n')[1].Trim();

                    if (string.IsNullOrWhiteSpace(Info))
                    {
                        return false;
                    }

                    return bool.Parse(Info);
                }

                public static bool IsSecureBootEnabled()
                {
                    string Info = RunPowerShellCommand("Confirm-SecureBootUEFI");

                    if (string.IsNullOrWhiteSpace(Info))
                    {
                        return false;
                    }

                    return bool.Parse(Info);
                }
            }

            public static class DefenderSetConfig
            {
                public static void EnableSmartScreen()
                {
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "On", RegistryValueKind.String);
                    DeleteRegristyFolderTree(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System");
                }

                public static void DisableSmartScreen()
                {
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Off", RegistryValueKind.String);
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", "0", RegistryValueKind.DWord);
                }
            }

            [StructLayoutAttribute(LayoutKind.Sequential)]
            private struct SID_IDENTIFIER_AUTHORITY
            {
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                public byte[] Value;
            }

            [StructLayoutAttribute(LayoutKind.Sequential)]
            private struct TRUSTEE
            { public System.IntPtr pMultipleTrustee; public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation; public TRUSTEE_FORM TrusteeForm; public TRUSTEE_TYPE TrusteeType; public IntPtr ptstrName; }

            [StructLayoutAttribute(LayoutKind.Sequential)]
            private struct EXPLICIT_ACCESS
            { public ACCESS_MASK grfAccessPermissions; public ACCESS_MODE grfAccessMode; public uint grfInheritance; public TRUSTEE Trustee; }

            [StructLayoutAttribute(LayoutKind.Sequential)]
            private struct TOKEN_PRIVILEGES
            {
                public uint PrivilegeCount; [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.Struct)]
                public LUID_AND_ATTRIBUTES[] Privileges;
            }

            [StructLayoutAttribute(LayoutKind.Sequential)]
            private struct LUID_AND_ATTRIBUTES
            { public LUID Luid; public uint Attributes; }

            [StructLayoutAttribute(LayoutKind.Sequential)]
            private struct LUID
            { public uint LowPart; public int HighPart; }

            private enum TRUSTEE_TYPE
            { TRUSTEE_IS_GROUP, }

            private enum TRUSTEE_FORM
            { TRUSTEE_IS_SID, }

            private enum MULTIPLE_TRUSTEE_OPERATION
            { }

            public enum SE_OBJECT_TYPE
            { SE_UNKNOWN_OBJECT_TYPE = 0, SE_FILE_OBJECT, SE_SERVICE, SE_PRINTER, SE_REGISTRY_KEY, SE_LMSHARE, SE_KERNEL_OBJECT, SE_WINDOW_OBJECT, SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_PROVIDER_DEFINED_OBJECT, SE_WMIGUID_OBJECT, SE_REGISTRY_WOW64_32KEY }

            [Flags]
            private enum ACCESS_MASK : uint
            { GENERIC_ALL = 0x10000000, }

            [Flags]
            private enum SECURITY_INFORMATION : uint
            { OWNER_SECURITY_INFORMATION = 0x00000001, DACL_SECURITY_INFORMATION = 0x00000004, }

            private enum ACCESS_MODE
            { SET_ACCESS }

            private const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege"; private static SID_IDENTIFIER_AUTHORITY SECURITY_NT_AUTHORITY = new SID_IDENTIFIER_AUTHORITY() { Value = new byte[] { 0, 0, 0, 0, 0, 5 } }; private const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020; private const int NO_INHERITANCE = 0x0; private const int SECURITY_BUILTIN_DOMAIN_RID = 0x00000020; private const int DOMAIN_ALIAS_RID_ADMINS = 0x00000220; private const int TOKEN_QUERY = 8; private const int SE_PRIVILEGE_ENABLED = 2; [DllImportAttribute("advapi32.dll", EntryPoint = "OpenProcessToken")]
            [return: MarshalAsAttribute(UnmanagedType.Bool)]
            private static extern bool OpenProcessToken([InAttribute]

IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle); [DllImportAttribute("advapi32.dll", EntryPoint = "AllocateAndInitializeSid")]

            [return: MarshalAsAttribute(UnmanagedType.Bool)]
            private static extern bool AllocateAndInitializeSid([InAttribute] ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority, byte nSubAuthorityCount, uint nSubAuthority0, uint nSubAuthority1, uint nSubAuthority2, uint nSubAuthority3, uint nSubAuthority4, uint nSubAuthority5, uint nSubAuthority6, uint nSubAuthority7, ref IntPtr pSid); [DllImportAttribute("kernel32.dll", EntryPoint = "CloseHandle")]

            [return: MarshalAsAttribute(UnmanagedType.Bool)]
            private static extern bool CloseHandle([InAttribute] IntPtr hObject); [DllImportAttribute("kernel32.dll", EntryPoint = "GetCurrentProcess")]
            private static extern IntPtr GetCurrentProcess(); [DllImportAttribute("advapi32.dll", EntryPoint = "FreeSid")]
            private static extern IntPtr FreeSid([InAttribute] IntPtr pSid); [DllImportAttribute("kernel32.dll", EntryPoint = "LocalFree")]
            private static extern IntPtr LocalFree(IntPtr hMem); [DllImportAttribute("advapi32.dll", EntryPoint = "LookupPrivilegeValueA")]

            [return: MarshalAsAttribute(UnmanagedType.Bool)]
            private static extern bool LookupPrivilegeValueA([InAttribute]
[MarshalAsAttribute(UnmanagedType.LPStr)]
string lpSystemName, [InAttribute]
[MarshalAsAttribute(UnmanagedType.LPStr)]
string lpName, [OutAttribute]

out LUID lpLuid); [DllImportAttribute("advapi32.dll", EntryPoint = "AdjustTokenPrivileges")]

            [return: MarshalAsAttribute(UnmanagedType.Bool)]
            private static extern bool AdjustTokenPrivileges([InAttribute()]
IntPtr TokenHandle, [MarshalAsAttribute(UnmanagedType.Bool)]
bool DisableAllPrivileges, [InAttribute()]

ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength); [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
            private static extern int SetNamedSecurityInfo(string pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl); [DllImport("Advapi32.dll", EntryPoint = "SetEntriesInAclA", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Ansi)]
            private static extern int SetEntriesInAcl(int CountofExplicitEntries, ref EXPLICIT_ACCESS ea, IntPtr OldAcl, ref IntPtr NewAcl);
        }

        /*powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableRealtimeMonitoring $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableRemovableDriveScanning $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableArchiveScanning $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableArchiveScanning $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableAutoExclusions $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableBehaviorMonitoring $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableBlockAtFirstSeen $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableCatchupFullScan $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableCatchupQuickScan $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableCpuThrottleOnIdleScans $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableDatagramProcessing $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableDnsOverTcpParsing $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableDnsParsing $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableEmailScanning $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableGradualRelease $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableHttpParsing $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableInboundConnectionFiltering $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableIOAVProtection $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableNetworkProtectionPerfTelemetry $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisablePrivacyMode $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableRdpParsing $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableRealtimeMonitoring $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableRemovableDriveScanning $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableRestorePoint $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableScanningNetworkFiles $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableScriptScanning $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableSshParsing $false"
powershell.exe -ExecutionPolicy Bypass -command "Set-MpPreference -DisableTlsParsing $false"  */
    }
}