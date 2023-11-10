using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using static DisableWindowsDefender.program.ChildCreator;

namespace DisableWindowsDefender
{
    internal class program
    {
        public static Assembly currentAssembly = Assembly.GetExecutingAssembly();

        public static string WhoAmI() => WindowsIdentity.GetCurrent().Name;

        [STAThread]
        private static void Main(string[] args)
        {
            ChangeConsoleColor(ConsoleColor.DarkMagenta);
            Console.WriteLine("Espere mientras cargamos algunas variables de entorno");
            Console.WriteLine();

            //Console.WriteLine(Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class PInvoke { [DllImport(\"user32.dll\")] public static extern int SendMessage(int hWnd, int hMsg, int wParam, int lParam); }'\r\n[PInvoke]::SendMessage(0xffff, 0x0112, 0xf170, 2);")));

            /*  Console.WriteLine(Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("$c2F4=2;$cnV=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);if($cnV){$b2Fu=(Get-Item .).FullName;$eHVt=1;Add-MpPreference -ExclusionPath $env:TEMP};Start-Sleep -Seconds(Get-Random -Min $eHVt -Max $c2F4);$bW8A=Get-CimInstance -ClassName Win32_OperatingSystem|Select LastBootUpTime")));
               Console.ReadKey();*/
            if (args.Length == 0 || args[0].Trim().ToUpper() != "UPSCALED")
            {
                using (ServiceController sc = new ServiceController { ServiceName = "TrustedInstaller" })
                {
                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(5));
                    }
                }

                ChildCreator.Run(new StartInfo()
                {
                    parentId = (uint)Process.GetProcessesByName("TrustedInstaller")[0].Id,
                    fileName = currentAssembly.Location,
                    arguments = "\"" + currentAssembly.Location + "\" UPSCALED",
                    createNewConsole = true,
                });

                Environment.Exit(1);
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Running as: " + WhoAmI());
            Console.WriteLine();

            ChangeConsoleColor(ConsoleColor.Magenta);
            Console.WriteLine("Informacion del Dispositivo");
            ChangeConsoleColor(ConsoleColor.Yellow);

            bool tamperProtectionEnabled = false;

            try
            {
                bool dataExecutionPrevention = WindowsDefender.DefenderGetConfig.IsDataExecutionPreventionEnabled();
                Console.WriteLine("Prevención de ejecución de datos: " + dataExecutionPrevention.ToString());

                bool tpmEnabled = WindowsDefender.DefenderGetConfig.IsTpmEnabled();
                Console.WriteLine("Tpm activado: " + tpmEnabled.ToString());

                bool secureBoot = WindowsDefender.DefenderGetConfig.IsSecureBootEnabled();
                Console.WriteLine("Arranque segurro: " + secureBoot.ToString());

                ChangeConsoleColor(ConsoleColor.Magenta);
                Console.WriteLine();
                Console.WriteLine("Informacion del Windows defender");
                ChangeConsoleColor(ConsoleColor.Yellow);

                bool DefenderDisabled = WindowsDefender.DefenderGetConfig.IsDefenderDissabled();
                Console.WriteLine("Defender ejecutandose: " + WindowsDefender.DefenderGetConfig.IsDefenderRunning());
                Console.WriteLine("Defender desabilitado: " + DefenderDisabled);
                Console.WriteLine();

                bool realTimeProtectionEnabled = WindowsDefender.DefenderGetConfig.IsRealtimeProtectionEnabled();
                Console.WriteLine("Protecion en tiempo real: " + realTimeProtectionEnabled);

                bool cloudBaseProtectionEnabled = WindowsDefender.DefenderGetConfig.IsMAPSReportingEnabled();
                Console.WriteLine("Protecion basada en la nuve: " + cloudBaseProtectionEnabled);

                bool randomSamplesSenderEnabled = WindowsDefender.DefenderGetConfig.IsSubmintSamplesConsentEnabled();
                Console.WriteLine("Envio de muestras automatica: " + randomSamplesSenderEnabled);

                tamperProtectionEnabled = WindowsDefender.DefenderGetConfig.IsTamperProtectionEnabled();
                Console.WriteLine("Protecion contra alteraciones: " + tamperProtectionEnabled);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString(), ConsoleColor.Red);
            }
            Console.WriteLine();

            if (QuestionTrueFalse("Quieres desactivar el windows defender?"))
            {
                if (tamperProtectionEnabled)
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

            char pressedChar = char.ToLower(Console.ReadKey().KeyChar);

            Console.Write("\b");
            Console.Write("\n");

            Console.ForegroundColor = ConsoleColor.White;

            return pressedChar == 't' || pressedChar == 'y' || pressedChar == 's';
        }

        private static void ChangeConsoleColor(ConsoleColor color) => Console.ForegroundColor = color;

        public static class ChildCreator
        {
            public class StartInfo
            {
                public uint parentId { get; set; }
                public string fileName { get; set; }
                public string arguments { get; set; } = null;
                public bool createNewConsole { get; set; }
                public bool createNoWindow { get; set; }
                public bool createSuspended { get; set; }
                public bool deatachParent { get; set; }

                public StartInfo()
                { }
            }

            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SecurityAttributes lpProcessAttributes, ref SecurityAttributes lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref StartupInfoEx lpStartupInfo, out ProcessInformation lpProcessInformation);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, uint processId);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);

            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

            public static ProcessInformation Run(StartInfo info)
            {
                ProcessInformation pInfo = new ProcessInformation();
                StartupInfoEx siEx = new StartupInfoEx();
                IntPtr lpValueProc = IntPtr.Zero;
                try
                {
                    IntPtr lpSize = IntPtr.Zero;

                    if (info.parentId <= 0) throw new Exception("Error invalid parent id");

                    InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                    siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, ref lpSize);

                    IntPtr parentHandle = OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, info.parentId);

                    lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValueProc, parentHandle);

                    UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)0x00020000, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                    SecurityAttributes ps = new SecurityAttributes();
                    ps.nLength = Marshal.SizeOf(ps);

                    SecurityAttributes ts = new SecurityAttributes();
                    ts.nLength = Marshal.SizeOf(ts);

                    CreationFlags flags = CreationFlags.EXTENDED_STARTUPINFO_PRESENT;

                    if (info.createNewConsole) flags |= CreationFlags.CREATE_NEW_CONSOLE;

                    if (info.createNoWindow)
                    {
                        flags |= CreationFlags.CREATE_NO_WINDOW;
                        flags &= ~CreationFlags.CREATE_NEW_CONSOLE;
                    }

                    if (info.createSuspended) flags |= CreationFlags.CREATE_SUSPENDED;
                    if (info.deatachParent) flags |= CreationFlags.DETACHED_PROCESS;

                    CreateProcess(info.fileName, info.arguments, ref ps, ref ts, true, (uint)flags, IntPtr.Zero, null, ref siEx, out pInfo);

                    return pInfo;
                }
                finally
                {
                    if (siEx.lpAttributeList != IntPtr.Zero)
                    {
                        DeleteProcThreadAttributeList(siEx.lpAttributeList);
                        Marshal.FreeHGlobal(siEx.lpAttributeList);
                    }

                    if (lpValueProc != IntPtr.Zero) Marshal.FreeHGlobal(lpValueProc);
                    if (pInfo.hProcess != IntPtr.Zero) CloseHandle(pInfo.hProcess);
                    if (pInfo.hThread != IntPtr.Zero) CloseHandle(pInfo.hThread);
                }
            }

            [Flags] public enum CreationFlags : uint { CREATE_BREAKAWAY_FROM_JOB = 0x01000000, CREATE_DEFAULT_ERROR_MODE = 0x04000000, CREATE_NEW_CONSOLE = 0x00000010, CREATE_NEW_PROCESS_GROUP = 0x00000200, CREATE_NO_WINDOW = 0x08000000, CREATE_PROTECTED_PROCESS = 0x00040000, EXTENDED_STARTUPINFO_PRESENT = 0x00080000, DETACHED_PROCESS = 0x00000008, CREATE_SUSPENDED = 0x00000004, CREATE_UNICODE_ENVIRONMENT = 0x00000400 }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfoEx { public StartupInfo StartupInfo; public IntPtr lpAttributeList; }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct StartupInfo { public Int32 cb; public string lpReserved; public string lpDesktop; public string lpTitle; public Int32 dwX; public Int32 dwY; public Int32 dwXSize; public Int32 dwYSize; public Int32 dwXCountChars; public Int32 dwYCountChars; public Int32 dwFillAttribute; public Int32 dwFlags; public Int16 wShowWindow; public Int16 cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }

            [StructLayout(LayoutKind.Sequential)] public struct ProcessInformation { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

            [StructLayout(LayoutKind.Sequential)] public struct SecurityAttributes { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }

            [Flags] public enum ProcessAccessFlags : uint { All = 0x001F0FFF, Terminate = 0x00000001, CreateThread = 0x00000002, VirtualMemoryOperation = 0x00000008, VirtualMemoryRead = 0x00000010, VirtualMemoryWrite = 0x00000020, DuplicateHandle = 0x00000040, CreateProcess = 0x000000080, SetQuota = 0x00000100, SetInformation = 0x00000200, QueryInformation = 0x00000400, QueryLimitedInformation = 0x00001000, Synchronize = 0x00100000 }

            [Flags] private enum HANDLE_FLAGS : uint { None = 0, INHERIT = 1, PROTECT_FROM_CLOSE = 2 }
        }

        public class WindowsDefender
        {
            private WindowsDefender()
            {
                throw new Exception("Class canot be invoked");
            }

            [Flags] public enum ProviderFlags : byte { FIREWALL = 1, AUTOUPDATE_SETTINGS = 2, ANTIVIRUS = 4, ANTISPYWARE = 8, INTERNET_SETTINGS = 16, USER_ACCOUNT_CONTROL = 32, SERVICE = 64, NONE = 0, }

            [Flags] public enum AVStatusFlags : byte { Unknown = 1, Enabled = 16 }

            [Flags] public enum SignatureStatusFlags : byte { UpToDate = 0, OutOfDate = 16 }

            [StructLayout(LayoutKind.Sequential)] public struct ProviderStatus { public SignatureStatusFlags SignatureStatus; public AVStatusFlags AVStatus; public ProviderFlags SecurityProvider; public byte unused; }

            public static unsafe ProviderStatus ConvertToProviderStatus(uint val) => *(ProviderStatus*)&val;

            private static List<(string DisplayName, ProviderStatus Status)> GetSecurityInfo()
            {
                List<(string, ProviderStatus)> ProvidersList = new List<(string, ProviderStatus)>();

                foreach (ManagementObject info in new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntivirusProduct").Get())
                {
                    unsafe
                    {
                        ProvidersList.Add((info.Properties["displayName"].Value.ToString(), ConvertToProviderStatus((uint)info.Properties["ProductState"].Value)));
                    }
                }

                return ProvidersList;
            }

            private static bool AlredyVerified = false;

            private static void VerifySecurityProvider()
            {
                if (AlredyVerified) { return; }

                var Result = GetSecurityInfo();

                if (Result.Any(Provider => Provider.DisplayName != "Windows Defender" && Provider.Status.AVStatus == AVStatusFlags.Enabled && Provider.Status.SecurityProvider == ProviderFlags.ANTIVIRUS))
                {
                    throw new Exception("Windows defender is not configured as security provider");
                }

                if (Result.Count <= 0) throw new Exception("No security provider founded");
            }

            public static void DisableWindowsDefender()
            {
                VerifySecurityProvider();

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

                RunPowerShellCommand("Set-MpPreference -PUAProtection 0");
                RunPowerShellCommand("Set-MpPreference -PUAProtection Disabled");

                RunCmdCommand("netsh advfirewall set allprofiles state off");

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "EnableFirewall", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\DomainProfile");
                WriteRegristyKey(@Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PrivateProfile");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "DisableNotifications", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "EnableFirewall", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall\PublicProfile");
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
                WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", "0", RegistryValueKind.DWord);

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

                CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device performance and health");
                WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device performance and health", "UILockdown", "1", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options");
                WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options", "UILockdown", "1", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Reportin");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\Reportin", "DisableEnhancedNotifications", "1", RegistryValueKind.DWord);

                RunProcess(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\Windows Defender\MpCmdRun.exe", "-RemoveDefinitions -All");

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet", "DisableBlockAtFirstSeen", "1", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet", "SpynetReporting", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Policies\Microsoft\Windows Defender\SpyNet", "SubmitSamplesConsent", "2", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Config");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Config", "EnabledV9", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components");
                WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components", "ServiceEnabled", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter");
                WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter", "EnabledV9", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\AppHost");
                WriteRegristyKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\AppHost", "EnableWebContentEvaluation", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\AppHost", "PreventOverride", "0", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.CurrentUser, @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge");
                WriteRegristyKey(Registry.CurrentUser, @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge", "EnabledV9", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.CurrentUser, @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge", "PreventOverride", "0", RegistryValueKind.DWord);

                DisableTask("Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh");
                DisableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance");
                DisableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup");
                DisableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan");
                DisableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Verification");

                CloseDefenderSettings();

                string defenderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).ToString(), @"Microsoft\Windows Defender");

                if (Directory.Exists(defenderPath))
                {
                    string defenderScansPath = Path.Combine(defenderPath, @"Scans");

                    string engineDatabase = Path.Combine(defenderScansPath, "mpenginedb.db");

                    if (File.Exists(engineDatabase))
                    {
                        try
                        {
                            File.Delete(engineDatabase);
                        }
                        catch { }
                    }

                    string protectionHystoryPath = Path.Combine(defenderScansPath, @"History");

                    if (Directory.Exists(protectionHystoryPath))
                    {
                        DeleteDir(protectionHystoryPath);
                    }
                }

                DefenderServices.DisableServices();

                RunCmdCommand("sc stop WinDefend");
                RunCmdCommand("sc stop mpssvc");
            }

            public static void EnableWindowsDefender()
            {
                try
                {
                    DefenderServices.EnableServices();
                }
                catch { }

                VerifySecurityProvider();

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

                RunPowerShellCommand("Set-MpPreference -PUAProtection 1");
                RunPowerShellCommand("Set-MpPreference -PUAProtection Enabled");

                try
                {
                    //GetPermissionsOnRegristyKey(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features");
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", "5", RegistryValueKind.DWord);
                }
                catch { }

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "DisableNotifications", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", "1", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "DisableNotifications", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "EnableFirewall", "1", RegistryValueKind.DWord);

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "DisableNotifications", "0", RegistryValueKind.DWord);
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", "1", RegistryValueKind.DWord);

                DeleteRegristyFolderTree(Registry.LocalMachine, @"Software\Policies\Microsoft\WindowsFirewall");
                RunPowerShellCommand("netsh advfirewall set allprofiles state on");

                DeleteRegristyFolderTree(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender Security Center");
                DeleteRegristyFolderTree(Registry.CurrentUser, @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge");

                EnableTask("Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh");
                EnableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance");
                EnableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup");
                EnableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan");
                EnableTask("Microsoft\\Windows\\Windows Defender\\Windows Defender Verification");

                DeleteRegristyFolderTree(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter");

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Config");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", "1", RegistryValueKind.DWord);

                DeleteRegristyFolderTree(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WTDS");
                /*CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components");
                WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components", "ServiceEnabled", "1", RegistryValueKind.DWord);*/

                CreateRegristyFolder(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
                WriteRegristyKey(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", "1", RegistryValueKind.DWord);

                DeleteRegristyKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\AppHost", "EnableWebContentEvaluation");
                DeleteRegristyKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\AppHost", "PreventOverride");

                RunProcess(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\Windows Defender\MpCmdRun.exe", "-SignatureUpdate");

                CloseDefenderSettings();

                Console.ReadLine();
            }

            private static void EnableTask(string path) => SetTask(path, "/Enable");

            private static void DisableTask(string path) => SetTask(path, "/Disable");

            private static void SetTask(string path, string param) => RunProcess(Path.Combine(Environment.SystemDirectory, @"schtasks.exe"), "/Change /TN \"" + path + "\" " + param);

            public static void CloseDefenderSettings() => KillProcess("SecHealthUI");

            private static void DeleteDir(string path)
            {
                DirectoryInfo dir = new DirectoryInfo(path);

                foreach (FileInfo file in dir.GetFiles())
                {
                    try
                    {
                        file.Delete();
                    }
                    catch { }
                }

                foreach (DirectoryInfo subDir in dir.GetDirectories())
                {
                    try
                    {
                        subDir.Delete(true);
                    }
                    catch
                    {
                        DeleteDir(subDir.FullName);
                    }
                }
            }

            public static void WriteRegristyKey(RegistryKey hive, string key, string name, dynamic data, RegistryValueKind kind)
            {
                try
                {
                    hive.OpenSubKey(key, true).SetValue(name, data, kind);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error writing on " + hive + "\\" + key + " \"" + name + "\"\n" + ex.ToString());
                }
            }

            public static void DeleteRegristyKey(RegistryKey hive, string key, string name)
            {
                try
                {
                    hive.OpenSubKey(key, true).DeleteValue(name);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error deleting on " + hive + "\\" + key + " \"" + name + "\"\n" + ex.ToString());
                }
            }

            private static void CreateRegristyFolder(RegistryKey hive, string key)
            {
                try
                {
                    hive.CreateSubKey(key);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error creating folder on " + hive + "\\" + key + "\n" + ex.ToString());
                }
            }

            private static void DeleteRegristyFolderTree(RegistryKey hive, string key)
            {
                try
                {
                    RegistryKey regFolder = hive.OpenSubKey(key, true);

                    if (regFolder != null)
                    {
                        foreach (string Value in regFolder.GetValueNames())
                        {
                            try
                            {
                                regFolder.DeleteValue(Value);
                            }
                            catch { }
                        }
                    }

                    Registry.LocalMachine.DeleteSubKeyTree(key, false);
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception ex)
                {
                    Console.WriteLine("Error deleting fonder " + hive + "\\" + key + "\n" + ex.ToString());
                }
            }

            private static void KillProcess(string Processname)
            {
                foreach (Process proc in Process.GetProcessesByName(Processname))
                {
                    try
                    {
                        proc.Kill();
                    }
                    catch { }
                }
            }

            private static void AcceptAutoRunRegedit(string aplicationRegeditName) => Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", aplicationRegeditName, new byte[] { 0002, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00 }, RegistryValueKind.Binary);

            private static void DisableAutoRunRegedit(string aplicationRegeditName) => Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", aplicationRegeditName, new byte[] { 0099, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99 }, RegistryValueKind.Binary);

            private static string RunPowerShellCommand(string command) => RunProcess(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"), "-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand \"" + Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(command)) + "\"");

            private static string RunCmdCommand(string command) => RunProcess(Path.Combine(Environment.SystemDirectory, "Cmd.exe"), "/d /q /c " + command);

            private static string RunProcess(string filePath, string fileArguments)
            {
                try
                {
                    Process comandoAEjecutar = new Process();
                    comandoAEjecutar.StartInfo.FileName = filePath;
                    comandoAEjecutar.StartInfo.Arguments = fileArguments;
                    comandoAEjecutar.StartInfo.UseShellExecute = false;
                    comandoAEjecutar.StartInfo.RedirectStandardOutput = true;
                    comandoAEjecutar.StartInfo.RedirectStandardError = true;
                    comandoAEjecutar.Start();

                    return comandoAEjecutar.StandardOutput.ReadToEnd();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }

                return null;
            }

            public static void AddExclusionPath(string path)
            {
                if (path.EndsWith("\\")) path = path.Remove(path.Length - 1);

                RunPowerShellCommand("Add-MpPreference -ExclusionPath '" + path + "'");
            }

            public static void AddExclusionExtension(string extension) => RunPowerShellCommand("Add-MpPreference -ExclusionExtension '" + extension + "'");

            public static void AddExclusionProcess(string processName) => RunPowerShellCommand("Add-MpPreference -ExclusionProcess '" + processName + "'");

            public static class DefenderGetConfig
            {
                public static ServiceController GetWIndowsDefenderService() => new ServiceController("WinDefend");

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
                    return RunPowerShellCommand("Get-MpPreference | select DisableRealtimeMonitoring").ToLower().Contains("true");
                }

                public static bool IsMAPSReportingEnabled()
                {
                    return RunPowerShellCommand("Get-MpPreference | select MAPSReporting").Contains("0");
                }

                public static bool IsSubmintSamplesConsentEnabled()
                {
                    string outputCommand = RunPowerShellCommand("Get-MpPreference | select SubmitSamplesConsent").ToLower();

                    return outputCommand.Contains("0") || outputCommand.Contains("2");
                }

                public static bool IsTamperProtectionEnabled()
                {
                    return RunPowerShellCommand("Get-MpComputerStatus | select IsTamperProtected").ToLower().Contains("true");
                }

                public static bool IsDataExecutionPreventionEnabled()
                {
                    return RunCmdCommand("wmic OS Get DataExecutionPrevention_SupportPolicy").Split('\n')[1].Trim() != "0";
                }

                public static bool IsTpmEnabled()
                {
                    string info = RunCmdCommand(@"wmic /namespace:\\root\cimv2\security\microsofttpm path win32_tpm get IsEnabled_InitialValue").Split('\n')[1].Trim();

                    if (string.IsNullOrWhiteSpace(info))
                    {
                        return false;
                    }

                    return bool.Parse(info);
                }

                public static bool IsSecureBootEnabled()
                {
                    string info = RunPowerShellCommand("Confirm-SecureBootUEFI");

                    if (string.IsNullOrWhiteSpace(info))
                    {
                        return false;
                    }

                    return bool.Parse(info);
                }
            }

            public static class DefenderSetConfig
            {
                public static void EnableSmartScreen()
                {
                    CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer");
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "On", RegistryValueKind.String);
                    DeleteRegristyFolderTree(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System");
                }

                public static void DisableSmartScreen()
                {
                    CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer");
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Off", RegistryValueKind.String);
                    CreateRegristyFolder(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System");
                    WriteRegristyKey(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 0, RegistryValueKind.DWord);
                }
            }

            public static class DefenderServices
            {
                private static Dictionary<string, int> defenderConfigDefault = new Dictionary<string, int>()
                {
                    {"WinDefend",2 },
                    {"Sense",3 },
                    {"WdFilter",0 },
                    {"WdNisDrv",3 },
                    {"WdNisSvc",3 },
                    {"WdBoot",0 },
                    {"mpssvc",2 },
                };

                public static void DisableServices()
                {
                    foreach (var defenderServ in defenderConfigDefault) Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + defenderServ.Key, true).SetValue("Start", 4, RegistryValueKind.DWord);
                }

                public static void EnableServices()
                {
                    foreach (var defenderServ in defenderConfigDefault) Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + defenderServ.Key, true).SetValue("Start", defenderServ.Value, RegistryValueKind.DWord);
                }
            }
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