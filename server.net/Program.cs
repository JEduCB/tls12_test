// See https://aka.ms/new-console-template for more information

using System;
using System.Runtime.InteropServices;

namespace Server
{
    static class Program
    {
        [DllImport("server_lib.so", EntryPoint="run_server", CharSet = CharSet.Ansi, SetLastError = true, CallingConvention=CallingConvention.Cdec‌​l)]
        private static extern int run_server(string port, string job_mode, string payload, string pem_public_file, string pem_private_file);
       
        static int Main(string[] argv)
        {
            if(argv.Length != 3)
            {
                Console.WriteLine("Usage: server.net <portnum> <sync | async> <payload>");
                return 1;
            }

            run_server(argv[0], argv[1], argv[2], "yarp.qat+5.pem", "yarp.qat+5-key.pem");

            return 0;
        }
    }
}