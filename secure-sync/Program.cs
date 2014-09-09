using System;
using System.Net;
using System.Diagnostics;

using SecureSync;

namespace Program
{
    class Program
    {
        public static string SendResponse(HttpListenerRequest request)
        {
            return string.Format("<HTML><BODY>My web page.<br>{0}</BODY></HTML>", DateTime.Now);
        }

        static void Main()
        {
            try
            {
                Windows_HTTP_Server ws = new Windows_HTTP_Server(SendResponse, @"http://localhost:8080/test/");
                ws.Run();
                Console.WriteLine("A simple webserver. Press a key to quit.");
                Console.ReadKey();
                ws.Stop();
            }
            catch (Exception e)
            {
                Throw_Exceptions.Throw_Exception_Error("", e);
            }
        }
    }
}