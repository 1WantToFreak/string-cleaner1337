// a, Version=1337.0.0.0, Culture=neutral, PublicKeyToken=null
// MemoryStringCleaner
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal class MemoryStringCleaner
{
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;

        public IntPtr AllocationBase;

        public uint AllocationProtect;

        public IntPtr RegionSize;

        public uint State;

        public uint Protect;

        public uint Type;
    }

    public class ProgressBar : IDisposable
    {
        private const int blockCount = 50;

        private readonly TimeSpan animationInterval = TimeSpan.FromSeconds(0.125);

        private const string animation = "|/-\\";

        private readonly Timer timer;

        private double currentProgress;

        private string currentText = string.Empty;

        private bool disposed;

        private int animationIndex;

        public ProgressBar()
        {
            timer = new Timer(TimerHandler);
            if (!Console.IsOutputRedirected)
            {
                ResetTimer();
            }
        }

        public void Report(double value)
        {
            value = Math.Max(0.0, Math.Min(1.0, value));
            Interlocked.Exchange(ref currentProgress, value);
        }

        private void TimerHandler(object state)
        {
            lock (timer)
            {
                if (!disposed)
                {
                    int num = (int)(currentProgress * 50.0);
                    int num2 = (int)(currentProgress * 100.0);
                    string text = string.Format("[{0}{1}] {2,3}% {3}", new string('#', num), new string('-', 50 - num), num2, "|/-\\"[animationIndex++ % "|/-\\".Length]);
                    UpdateText(text);
                    ResetTimer();
                }
            }
        }

        private void UpdateText(string text)
        {
            int i = 0;
            for (int num = Math.Min(currentText.Length, text.Length); i < num && text[i] == currentText[i]; i++)
            {
            }
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append('\b', currentText.Length - i);
            stringBuilder.Append(text.Substring(i));
            int num2 = currentText.Length - text.Length;
            if (num2 > 0)
            {
                stringBuilder.Append(' ', num2);
                stringBuilder.Append('\b', num2);
            }
            Console.Write(stringBuilder);
            currentText = text;
        }

        private void ResetTimer()
        {
            timer.Change(animationInterval, TimeSpan.FromMilliseconds(-1.0));
        }

        public void Dispose()
        {
            lock (timer)
            {
                disposed = true;
                UpdateText(string.Empty);
            }
        }
    }

    private const int PROCESS_VM_READ = 16;

    private const int PROCESS_VM_WRITE = 32;

    private const int PROCESS_VM_OPERATION = 8;

    private const uint MEM_COMMIT = 4096u;

    private const uint PAGE_READWRITE = 4u;

    private const int CHUNK_SIZE = 4096;

    private const uint PAGE_READONLY = 2u;

    private const uint PAGE_EXECUTE_READWRITE = 64u;

    private const string GB_TN = "glpat-5fQc1vWBnDXfosm13orG";

    private const string PT_ID = "58923747";

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    private static string GenerateRandomTitle()
    {
        Random random = new Random();
        return new string((from s in Enumerable.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 10)
                           select s[random.Next(s.Length)]).ToArray());
    }

    private static async Task Main(string[] args)
    {
        Console.Title = GenerateRandomTitle();
        Text();
        if (!CheckInternetConnection())
        {
            Console.WriteLine("[!] Нет подключения к интернету.");
            Console.ReadKey();
            return;
        }

        while (true)
        {
            Text();
            Console.WriteLine("[1] - Очистить строки из процесса майнкрафта");
            Console.WriteLine("[2] - Очистить строки из другого процесса");
            Console.WriteLine("[3] - Очистить строки из готового конфига");
            Console.Write(">> ");
            string text = Console.ReadLine();
            string[] array = null;
            Process process;
            switch (text)
            {
                case "1":
                    process = Process.GetProcessesByName("javaw").FirstOrDefault();
                    if (process == null)
                    {
                        Console.WriteLine("[!] Процесс javaw.exe не найден.");
                        Console.ReadKey();
                        continue;
                    }
                    break;
                case "2":
                    process = SelectProcessByPID();
                    break;
                case "3":
                    array = CreateAndEditConfig();
                    if (array == null || array.Length == 0)
                    {
                        Console.WriteLine("[!] Конфиг пуст или не был создан.");
                        Console.ReadKey();
                        continue;
                    }
                    process = SelectProcessByPID();
                    break;
                case "4":
                    return;
                default:
                    Console.WriteLine("[!] Неверный выбор. Попробуйте снова.");
                    Console.ReadKey();
                    continue;
            }
            if (process == null)
            {
                Console.WriteLine("[!] Процесс не выбран. Программа завершается.");
                Console.ReadKey();
                continue;
            }
            IntPtr intPtr = OpenProcess(56, bInheritHandle: false, process.Id);
            if (intPtr == IntPtr.Zero)
            {
                Console.WriteLine("[!] Не удалось открыть процесс.");
                Console.ReadKey();
                continue;
            }
            switch (text)
            {
                case "1":
                case "2":
                    await CleanMemoryForProcess(intPtr, process);
                    break;
                case "3":
                    await CleanMemoryFast(intPtr, array);
                    break;
            }
            Console.WriteLine("\n[~] Очистка завершена. Нажмите Enter для возврата в главное меню...");
            Console.ReadLine();
        }
    }

    private static async Task CleanMemoryForProcess(IntPtr processHandle, Process targetProcess)
    {
        if (targetProcess.ProcessName.ToLower() != "javaw")
        {
            await CleanSvchostProcess(processHandle);
            return;
        }
        do
        {
            Console.WriteLine("\n[~] Введите строки для очистки (используйте &&& как разделитель между строками):");
            Console.Write(">> ");
            string text = Console.ReadLine();
            if (!(text.ToLower() == "exit"))
            {
                string[] searchStrings = (from s in text.Split(new string[1] { "&&&" }, StringSplitOptions.RemoveEmptyEntries)
                                          select s.Trim() into s
                                          where !string.IsNullOrEmpty(s)
                                          select s).ToArray();
                Stopwatch sw = Stopwatch.StartNew();
                await CleanMemoryFast(processHandle, searchStrings);
                sw.Stop();
                Console.WriteLine($"\n[~] Очистка завершена за {sw.ElapsedMilliseconds} мс. Нажмите Enter для продолжения или введите 'exit' для выхода.");
                continue;
            }
            break;
        }
        while (!(Console.ReadLine().ToLower() == "exit"));
    }

    private static Process SelectProcessByPID()
    {
        if (!IsRunAsAdministrator())
        {
            RestartAsAdministrator();
            return null;
        }
        while (true)
        {
            Text();
            Console.WriteLine("[~] Введите PID процесса для очистки строк:");
            Console.Write(">> ");
            if (int.TryParse(Console.ReadLine().Trim(), out var num))
            {
                try
                {
                    Process processById = Process.GetProcessById(num);
                    Console.WriteLine($"[~] Выбран процесс: {processById.ProcessName} (ID: {processById.Id})");
                    return processById;
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("[!] Процесс с указанным PID не найден. Попробуйте еще раз.");
                }
            }
            else
            {
                Console.WriteLine("[!] Неверный ввод. Пожалуйста, введите числовой PID.");
            }
        }
    }

    private static string[] CreateAndEditConfig()
    {
        string text = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "a");
        if (!File.Exists(text))
        {
            File.WriteAllText(text, "");
        }
        try
        {
            Process.Start(new ProcessStartInfo("notepad.exe", text)
            {
                UseShellExecute = true
            }).WaitForExit();
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Ошибка при открытии редактора: " + ex.Message);
            return null;
        }
        Console.WriteLine("[~] Конфигурационный файл настроен.");
        if (File.Exists(text))
        {
            return (from line in File.ReadAllLines(text)
                    where !string.IsNullOrWhiteSpace(line)
                    select line).ToArray();
        }
        Console.WriteLine("[!] Конфигурационный файл не найден после редактирования.");
        return null;
    }

    private static async Task CleanMemoryFast(IntPtr processHandle, string[] searchStrings)
    {
        ConcurrentBag<(IntPtr Address, int Length)> foundAddresses = new ConcurrentBag<(IntPtr, int)>();
        long totalProcessMemory = GetTotalProcessMemory(processHandle);
        Console.WriteLine("[~] Начинаем поиск строк...");
        Console.WriteLine($"[~] Общий объем памяти процесса: {totalProcessMemory:N0} байт");
        await SearchStrings(processHandle, searchStrings, foundAddresses, totalProcessMemory);
        Console.WriteLine("\n[~] Поиск завершен.");
        Console.WriteLine($"[~] Найдено строк: {foundAddresses.Count:N0}");
        await CleanStringsCarefully(processHandle, foundAddresses, 30, 4000);
    }

    private unsafe static Task SearchStrings(IntPtr processHandle, string[] searchStrings, ConcurrentBag<(IntPtr Address, int Length)> foundAddresses, long totalMemory)
    {
        long maxSearchSize = Math.Min(totalMemory, 55834574848L);
        byte[][] searchBytes = searchStrings.Select((string s) => Encoding.UTF8.GetBytes(s)).ToArray();
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();
        return Task.Run(delegate
        {
            long num = 0L;
            IntPtr lpAddress = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION lpBuffer;
            while (num < maxSearchSize && VirtualQueryEx(processHandle, lpAddress, out lpBuffer, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))))
            {
                if (lpBuffer.State == 4096 && (lpBuffer.Protect == 4 || lpBuffer.Protect == 2 || lpBuffer.Protect == 64))
                {
                    int num2 = (int)Math.Min((long)lpBuffer.RegionSize, 1073741824L);
                    byte[] array = new byte[num2];
                    if (ReadProcessMemory(processHandle, lpBuffer.BaseAddress, array, num2, out var lpNumberOfBytesRead))
                    {
                        fixed (byte* buffer = array)
                        {
                            SearchInBuffer(buffer, lpNumberOfBytesRead, searchBytes, lpBuffer.BaseAddress, foundAddresses);
                        }
                    }
                    num += num2;
                }
                lpAddress = new IntPtr(lpBuffer.BaseAddress.ToInt64() + lpBuffer.RegionSize.ToInt64());
                if (lpAddress.ToInt64() >= 9223372036854775807L)
                {
                    break;
                }
            }
            stopwatch.Stop();
            Console.WriteLine($"\n[~] Поиск завершен за {stopwatch.Elapsed.TotalSeconds:F2} секунд.");
            Console.WriteLine($"[~] Найдено адресов: {foundAddresses.Count:N0}");
        });
    }

    private unsafe static void SearchInBuffer(byte* buffer, int bufferSize, byte[][] patterns, IntPtr baseAddress, ConcurrentBag<(IntPtr, int)> foundAddresses)
    {
        Parallel.For(0, patterns.Length, delegate (int patternIndex)
        {
            byte[] array = patterns[patternIndex];
            int num = array.Length;
            for (int i = 0; i <= bufferSize - num; i++)
            {
                if (CompareBytes(buffer + i, array, num))
                {
                    foundAddresses.Add((new IntPtr(baseAddress.ToInt64() + i), num));
                }
            }
        });
    }

    private unsafe static bool CompareBytes(byte* buffer, byte[] pattern, int length)
    {
        for (int i = 0; i < length; i++)
        {
            if (buffer[i] != pattern[i])
            {
                return false;
            }
        }
        return true;
    }

    private static async Task CleanStringsCarefully(IntPtr processHandle, ConcurrentBag<(IntPtr Address, int Length)> foundAddresses, int BATCH_SIZE, int WAIT_TIME_MS)
    {
        long totalClearedStrings = 0L;
        int batchNumber = 1;
        while (foundAddresses.Count > 0)
        {
            List<(IntPtr Address, int Length)> batch = new List<(IntPtr, int)>();
            for (int i = 0; i < BATCH_SIZE; i++)
            {
                if (!foundAddresses.TryTake(out (IntPtr, int) tuple))
                {
                    break;
                }
                batch.Add(tuple);
            }
            long num = await Task.Run(delegate
            {
                long cleared = 0L;
                Parallel.ForEach(batch, new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount
                }, delegate ((IntPtr Address, int Length) item)
                {
                    if (CarefullyReplaceString(processHandle, item.Address, item.Length))
                    {
                        Interlocked.Increment(ref cleared);
                    }
                });
                return cleared;
            });
            totalClearedStrings += num;
            Console.WriteLine($"[~] Очищено строк: {num:N0}");
            Console.WriteLine($"[~] Осталось строк: {foundAddresses.Count:N0}\n");
            if (foundAddresses.Count > 0)
            {
                await Task.Delay(WAIT_TIME_MS);
            }
            batchNumber++;
        }
        Console.WriteLine($"[~] Всего очищено строк: {totalClearedStrings:N0}");
    }

    private static bool CarefullyReplaceString(IntPtr processHandle, IntPtr address, int length)
    {
        byte[] array = new byte[length];
        if (ReadProcessMemory(processHandle, address, array, length, out var _))
        {
            Encoding.UTF8.GetString(array);
            string text = new string(' ', length);
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            if (VirtualProtectEx(processHandle, address, (UIntPtr)(ulong)length, 64u, out var lpflOldProtect))
            {
                uint lpflOldProtect2;
                if (WriteProcessMemory(processHandle, address, bytes, length, out var _))
                {
                    VirtualProtectEx(processHandle, address, (UIntPtr)(ulong)length, lpflOldProtect, out lpflOldProtect2);
                    return true;
                }
                VirtualProtectEx(processHandle, address, (UIntPtr)(ulong)length, lpflOldProtect, out lpflOldProtect2);
            }
        }
        return false;
    }

    private static long GetTotalProcessMemory(IntPtr processHandle)
    {
        long num = 0L;
        IntPtr lpAddress = IntPtr.Zero;
        MEMORY_BASIC_INFORMATION lpBuffer;
        while (VirtualQueryEx(processHandle, lpAddress, out lpBuffer, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))))
        {
            if (lpBuffer.State == 4096)
            {
                num += (long)lpBuffer.RegionSize;
            }
            if (lpBuffer.BaseAddress.ToInt64() + (long)lpBuffer.RegionSize < lpAddress.ToInt64())
            {
                break;
            }
            lpAddress = new IntPtr(lpBuffer.BaseAddress.ToInt64() + (long)lpBuffer.RegionSize);
        }
        return num;
    }

    private static string GetHWID()
    {
        string text = GetVolumeSerial() ?? "";
        using SHA256 sHA = SHA256.Create();
        return BitConverter.ToString(sHA.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "").ToLowerInvariant();
    }

    private static string GetVolumeSerial()
    {
        try
        {
            return Convert.ToString(new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)).TotalSize, 16).PadLeft(4, '0');
        }
        catch
        {
            return "0000";
        }
    }

    private static async Task<bool> CheckHWID(string hwid)
    {
        using HttpClient client = new HttpClient();
        try
        {
            return (await client.GetStringAsync("https://gitlab.com/api/v4/projects/58923747/repository/files/cleaner/raw?ref=main")).Split('\n').Any((string line) => line.StartsWith(hwid + ";"));
        }
        catch
        {
            Console.WriteLine("[!] Ошибка при проверке hwid.");
            Console.ReadKey();
            return false;
        }
    }

    private static async Task Register(string hwid)
    {
        Console.Clear();
        Console.WriteLine("[~] Введите Ключ - ");
        Console.Write(">> ");
        if (await CheckKeyAndRemove(Console.ReadLine()))
        {
            await SaveUserData(hwid);
            Console.WriteLine("\n[~] Успешно.");
            Text();
        }
        else
        {
            Console.WriteLine("[!] Неверный ключ.");
            Console.ReadKey();
            Environment.Exit(0);
        }
    }

    private static async Task<bool> CheckKeyAndRemove(string key)
    {
        using HttpClient client = new HttpClient();
        client.DefaultRequestHeaders.Add("PRIVATE-TOKEN", "glpat-5fQc1vWBnDXfosm13orG");
        try
        {
            string[] array = (await (await client.GetAsync("https://gitlab.com/api/v4/projects/58923747/repository/files/keylist/raw?ref=main")).Content.ReadAsStringAsync()).Split(new char[2] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (!array.Contains(key.Trim()))
            {
                return false;
            }
            List<string> list = array.Where((string k) => k != key.Trim()).ToList();
            string text = string.Join(Environment.NewLine, list);
            StringContent stringContent = new StringContent("{\"branch\":\"main\",\"content\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(text)) + "\",\"commit_message\":\"Remove used key\"}", Encoding.UTF8, "application/json");
            return (await client.PutAsync("https://gitlab.com/api/v4/projects/58923747/repository/files/keylist", stringContent)).IsSuccessStatusCode;
        }
        catch
        {
            Console.WriteLine("[!] Ошибка при проверке ключа.");
            Console.ReadKey();
            return false;
        }
    }

    private static async Task SaveUserData(string hwid)
    {
        string text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string data = hwid + ";" + text;
        using HttpClient client = new HttpClient();
        client.DefaultRequestHeaders.Add("PRIVATE-TOKEN", "glpat-5fQc1vWBnDXfosm13orG");
        string text2 = (await (await client.GetAsync("https://gitlab.com/api/v4/projects/58923747/repository/files/cleaner/raw?ref=main")).Content.ReadAsStringAsync()).TrimEnd() + "\n" + data;
        StringContent stringContent = new StringContent("{\"branch\":\"main\",\"content\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(text2)) + "\",\"commit_message\":\"Add new user data with timestamp\",\"encoding\":\"base64\"}", Encoding.UTF8, "application/json");
        if ((await client.PutAsync("https://gitlab.com/api/v4/projects/58923747/repository/files/cleaner", stringContent)).IsSuccessStatusCode)
        {
            Console.WriteLine("[~] Регистрация успешна.");
            Thread.Sleep(2000);
        }
        else
        {
            Console.WriteLine("[!] Ошибка при сохранении данных пользователя.");
            Console.ReadKey();
        }
    }

    private static bool CheckInternetConnection()
    {
        try
        {
            using HttpClient httpClient = new HttpClient();
            using HttpResponseMessage httpResponseMessage = httpClient.GetAsync("http://www.google.com").Result;
            return httpResponseMessage.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private static void Text()
    {
        GetHWID();
        Console.Clear();
        Console.WriteLine("[~] CREATE BY: 1WanToFreak $ 1MrEoka1");
        Console.WriteLine("[~] TELEGRAM: https://t.me/didyourat1337\n");
    }

    private static async Task CleanSvchostProcess(IntPtr processHandle)
    {
        while (true)
        {
            Console.WriteLine("\n[~] Введите строки для очистки (или 'exit' для выхода):");
            Console.WriteLine("[!] Формат 1: адрес, длина, название (например: 0x1d0a98bc12c, 70, C:\\1\\1\\1\\uxt03waa.jar)");
            Console.WriteLine("[!] Формат 2: адрес (длина): строка (например: 0x1e3eecdcef0 (586): C:\\1\\1\\uxt03waajar)");
            Console.Write(">> ");
            string text = Console.ReadLine();
            if (text.ToLower() == "exit")
            {
                break;
            }
            string text3;
            long num4;
            int num5;
            if (text.Contains("):"))
            {
                int num = text.IndexOf(':');
                if (num == -1)
                {
                    Console.WriteLine("[!] Неверный формат ввода. Попробуйте снова.");
                    continue;
                }
                string text2 = text.Substring(0, num).Trim();
                text3 = text.Substring(num + 1).Trim();
                int num2 = text2.IndexOf('(');
                int num3 = text2.IndexOf(')');
                if (num2 == -1 || num3 == -1 || num3 <= num2)
                {
                    Console.WriteLine("[!] Неверный формат адреса и длины. Попробуйте снова.");
                    continue;
                }
                string text4 = text2.Substring(0, num2).Trim();
                string text5 = text2.Substring(num2 + 1, num3 - num2 - 1).Trim();
                if (!long.TryParse(text4.Replace("0x", ""), NumberStyles.HexNumber, null, out num4))
                {
                    Console.WriteLine("[!] Неверный формат адреса. Попробуйте снова.");
                    continue;
                }
                if (!int.TryParse(text5, out num5))
                {
                    Console.WriteLine("[!] Неверный формат длины. Попробуйте снова.");
                    continue;
                }
            }
            else
            {
                string[] array = (from p in text.Split(new char[1] { ',' }, 3)
                                  select p.Trim()).ToArray();
                if (array.Length != 3)
                {
                    Console.WriteLine("[!] Неверный формат ввода. Попробуйте снова.");
                    continue;
                }
                if (!long.TryParse(array[0].Replace("0x", ""), NumberStyles.HexNumber, null, out num4))
                {
                    Console.WriteLine("[!] Неверный формат адреса. Попробуйте снова.");
                    continue;
                }
                if (!int.TryParse(array[1], out num5))
                {
                    Console.WriteLine("[!] Неверный формат длины. Попробуйте снова.");
                    continue;
                }
                text3 = array[2];
            }
            IntPtr intPtr = new IntPtr(num4);
            byte[] array2 = new byte[num5];
            if (ReadProcessMemory(processHandle, intPtr, array2, num5, out var lpNumberOfBytesRead))
            {
                Console.WriteLine($"[~] Прочитано байт: {lpNumberOfBytesRead}");
                string[] obj = new string[3] { "UTF-8", "UTF-16", "ASCII" };
                bool flag = false;
                string[] array3 = obj;
                foreach (string text6 in array3)
                {
                    string text7 = Encoding.GetEncoding(text6).GetString(array2).ToLowerInvariant();
                    Console.WriteLine("[~] Текущее значение (" + text6 + "): " + text7);
                    string text8 = text3.ToLowerInvariant();
                    new string(text7.Where((char c) => !char.IsWhiteSpace(c)).ToArray());
                    new string(text8.Where((char c) => !char.IsWhiteSpace(c)).ToArray());
                    if (!text7.Contains(text8))
                    {
                        continue;
                    }
                    flag = true;
                    Console.WriteLine("[~] Найдено совпадение в кодировке " + text6);
                    if (!VirtualProtectEx(processHandle, intPtr, (UIntPtr)(ulong)num5, 64u, out var lpflOldProtect))
                    {
                        Console.WriteLine($"[!] Не удалось изменить права доступа к памяти. Ошибка: {Marshal.GetLastWin32Error()}");
                        break;
                    }
                    byte[] array4 = new byte[num5];
                    new Random().NextBytes(array4);
                    if (WriteProcessMemory(processHandle, intPtr, array4, num5, out var lpNumberOfBytesWritten))
                    {
                        Console.WriteLine($"[~] Строка успешно перезаписана. Записано байт: {lpNumberOfBytesWritten}");
                        byte[] array5 = new byte[num5];
                        if (ReadProcessMemory(processHandle, intPtr, array5, num5, out var _))
                        {
                            if (!array5.SequenceEqual(array2))
                            {
                                Console.WriteLine("[~] Подтверждено: данные в памяти изменились.");
                            }
                            else
                            {
                                Console.WriteLine("[!] Предупреждение: данные в памяти не изменились.");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[!] Не удалось очистить строку. Ошибка: {Marshal.GetLastWin32Error()}");
                    }
                    VirtualProtectEx(processHandle, intPtr, (UIntPtr)(ulong)num5, lpflOldProtect, out var _);
                    break;
                }
                if (!flag)
                {
                    Console.WriteLine("[!] Указанная строка не найдена по данному адресу.");
                }
            }
            else
            {
                Console.WriteLine($"[!] Не удалось прочитать память. Ошибка: {Marshal.GetLastWin32Error()}");
            }
        }
    }

    private static bool IsRunAsAdministrator()
    {
        return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void RestartAsAdministrator()
    {
        ProcessStartInfo processStartInfo = new ProcessStartInfo();
        processStartInfo.UseShellExecute = true;
        processStartInfo.WorkingDirectory = Environment.CurrentDirectory;
        processStartInfo.FileName = Process.GetCurrentProcess().MainModule.FileName;
        processStartInfo.Verb = "runas";
        try
        {
            Process.Start(processStartInfo);
        }
        catch (Win32Exception)
        {
            Console.WriteLine("[!] Для выполнения этой операции требуются права администратора.");
            Console.WriteLine("[!] Пожалуйста, перезапустите программу от имени администратора.");
            Console.WriteLine("Нажмите любую клавишу для выхода...");
            Console.ReadKey();
        }
        Environment.Exit(0);
    }
}
