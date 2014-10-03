using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;

namespace secure_sync.Server_Classes
{
    class WindowsHttpServer
    {
        private readonly HttpListener _listener = new HttpListener();
        private readonly Func<HttpListenerRequest, string> _responderMethod;

        public WindowsHttpServer
            (ICollection<string> prefixes, Func<HttpListenerRequest, string> method)
        {
            if (!HttpListener.IsSupported) 
                throw new NotSupportedException("Needs Windows XP SP2, Server 2003 or later.");

            if (prefixes == null || prefixes.Count == 0) 
                throw new ArgumentException("prefixes");

            if (method == null) 
                throw new ArgumentException("method");

            foreach (var s in prefixes) 
                _listener.Prefixes.Add(s);

            _responderMethod = method;

            _listener.Start();
        }

        public WindowsHttpServer
            (Func<HttpListenerRequest, string> method, params string[] prefixes)
            : this(prefixes, method)
        {
            // ---
        }

        public Boolean Run()
        {
            ThreadPool.QueueUserWorkItem((o) =>
            {
                Console.WriteLine("Webserver running.");
                try
                {
                    while (_listener.IsListening)
                    {
                        ThreadPool.QueueUserWorkItem((c) =>
                        {
                            var ctx = c as HttpListenerContext;
                            try
                            {
                                var rstr = _responderMethod(ctx.Request);
                                var buf = Encoding.UTF8.GetBytes(rstr);
                                ctx.Response.ContentLength64 = buf.Length;
                                ctx.Response.OutputStream.Write(buf, 0, buf.Length);
                            }
                            catch (Exception e)
                            {
                                ThrowExceptions.ThrowExceptionError("Unknown error.", e);
                            }
                            finally
                            {
                                if (ctx != null) ctx.Response.OutputStream.Close();
                            }
                        }, _listener.GetContext());
                    }
                }
                catch (Exception e)
                {
                    ThrowExceptions.ThrowExceptionError("Unknown error.", e);
                }
            });
            return true;
        }

        public Boolean Stop()
        {
            try
            {
                _listener.Stop();
                _listener.Close();
                return true;
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("", e);
            }
        }
    }
}
