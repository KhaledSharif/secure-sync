﻿using System;
using System.Net;
using secure_sync.Server_Classes;

namespace secure_sync
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
                var ws = new WindowsHttpServer(SendResponse, @"http://localhost:8080/test/");
                ws.Run();
                Console.WriteLine("A simple webserver. Press a key to quit.");
                Console.ReadKey();
                ws.Stop();
            }
            catch (Exception e)
            {
                ThrowExceptions.ThrowExceptionError("", e);
            }
        }
    }
}