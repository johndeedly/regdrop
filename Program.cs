using System;
using System.Buffers;
using System.Data;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Registry;
using toolbelt;

namespace regdrop
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 1)
            {
                Parallel.ForEach(args, new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount
                }, (arg) => ShellUtils.RunShellAsync(
                    "dotnet",
                    $"\"{Assembly.GetExecutingAssembly().Location}\" \"{arg}\"")
                    .GetAwaiter().GetResult()
                );
            }
            else if (args.Length == 1)
            {
                string arg = args[0];
                if (File.Exists(arg))
                {
                    ProcessFile(arg);
                }
            }
            else
            {
                Console.WriteLine(@"usage: regdrop [FILE]...");
                Console.WriteLine(@"creates a folder ""./regdrop"" and writes the analysis " +
                                  @"results inside subfolders named after their MD5 sums.");
            }
        }

        private static void ProcessFile(string arg)
        {
            FileInfo fi = new FileInfo(arg);
            if (fi.Length < 4 || !IsRegistryFile(arg))
            {
                return;
            }

            byte[] raw = File.ReadAllBytes(arg);
            RegistryHive reg = new RegistryHive(raw, arg)
            {
                RecoverDeleted = true,
                FlushRecordListsAfterParse = false
            };

            string name;
            using (FileStream fs = new FileStream(arg, FileMode.Open, FileAccess.Read))
            {
                name = Hashes.CalculateMD5FromStream(fs);
            }
            string path = $"regdrop/{name}";
            Directory.CreateDirectory(path);

            File.WriteAllText($"{path}/info.txt", reg.Header.ToString());

            if (!reg.Header.ValidateCheckSum())
            {
                Console.Error.WriteLine("Checksum validation error. Exiting.");
                return;
            }

            if (reg.Header.PrimarySequenceNumber != reg.Header.SecondarySequenceNumber)
            {
                string filePath = Path.GetDirectoryName(arg);
                string fileName = Path.GetFileNameWithoutExtension(arg);
                var logFiles = Directory.GetFiles(filePath, $"{fileName}.LOG?");

                if (logFiles.Length == 0)
                {
                    Console.Error.WriteLine($"[{arg}] Transaction logs missing. Exiting.");
                    return;
                }
                else
                {
                    reg.ProcessTransactionLogs(logFiles.ToList(), true);
                }
            }

            reg.ParseHive();

            string dumpFilePathTmp = $"{path}/dump.tmp";
            reg.ExportDataToCommonFormat(dumpFilePathTmp, false);

            string dumpFilePathCsv = $"{path}/dump.csv";
            string dumpFilePathJson = $"{path}/dump.json";
            using (DataTable dt = new DataTable())
            {
                dt.Columns.Add("type", typeof(string));
                dt.Columns.Add("active", typeof(string));
                dt.Columns.Add("offset", typeof(decimal));
                dt.Columns.Add("path", typeof(string));
                dt.Columns.Add("name", typeof(string));
                dt.Columns.Add("dataType", typeof(decimal));
                dt.Columns.Add("value", typeof(string));
                dt.Columns.Add("lastWriteTime", typeof(string));

                using (var fs = new FileStream(dumpFilePathTmp, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    dt.FromCsv(fs, false);
                }

                DataColumn type = dt.Columns["type"];
                foreach (var dr in dt.Rows
                    .OfType<DataRow>()
                    .Where(x => (string)x[type] == "value"))
                {
                    DataColumn dataType = dt.Columns["dataType"];
                    DataColumn value = dt.Columns["value"];
                    byte[] data = ConvertToBytes((string)dr[value]);
                    decimal dataTypeVal = (decimal)dr[dataType];

                    if (dataTypeVal == 0x2)
                    {
                        string txt = Encoding.Unicode.GetString(data).TrimEnd('\0');
                        dr[value] = txt;
                    }
                    else if (dataTypeVal == 0x4 && data.Length == 4)
                    {
                        int val = BitConverter.ToInt32(data);
                        dr[value] = val.ToString();
                    }
                    else if (dataTypeVal == 0x5 && data.Length == 4)
                    {
                        int val = BitConverter.ToInt32(data.Reverse().ToArray());
                        dr[value] = val.ToString();
                    }
                    else if (dataTypeVal == 0x7)
                    {
                        string txtlist = Encoding.Unicode.GetString(data).TrimEnd('\0');
                        string[] split = txtlist.Split('\0', StringSplitOptions.RemoveEmptyEntries);
                        dr[value] = string.Join("\n", split);
                    }
                    else if (dataTypeVal == 0xb && data.Length == 8)
                    {
                        long val = BitConverter.ToInt64(data);
                        dr[value] = val.ToString();
                    }
                    else
                    {
                        dr[value] = Convert.ToBase64String(data);
                    }
                }

                using (var fs = new FileStream(dumpFilePathCsv, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    dt.ToCsv(fs);
                }

                JsonDocument jdoc;
                dt.ToJson(out jdoc);
                using (var fs = new FileStream(dumpFilePathJson, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    Utf8JsonWriter writer = new Utf8JsonWriter(fs);
                    jdoc.WriteTo(writer);
                    writer.Flush();
                }
            }

            if (File.Exists(dumpFilePathTmp))
                File.Delete(dumpFilePathTmp);
        }

        private static byte[] ConvertToBytes(string str, char split = ' ')
        {
            if (str == null || str.Length < 2)
                return new byte[0];
            string[] arr = str.Split(split);
            byte[] data = new byte[arr.Length];
            for (int i = 0; i < arr.Length; i++)
                data[i] = Convert.ToByte(arr[i], 16);
            return data;
        }

        private static bool IsRegistryFile(string arg)
        {
            using (var fs = new FileStream(arg, FileMode.Open, FileAccess.Read))
            {
                using (var br = new BinaryReader(fs, new ASCIIEncoding()))
                {
                    try
                    {
                        var chunk = br.ReadBytes(4);

                        var sig = BitConverter.ToInt32(chunk, 0);

                        if (sig == 0x66676572)
                        {
                            return true;
                        }
                    }
                    catch (Exception)
                    {
                    }

                    return false;
                }
            }
        }
    }
}
