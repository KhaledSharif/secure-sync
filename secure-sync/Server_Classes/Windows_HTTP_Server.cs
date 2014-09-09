using System;
using System.Net;
using System.Web.Http;
using System.Threading;
using System.Linq;
using System.Text;

using SecureSync;

namespace SecureSync
{
    class Windows_HTTP_Server
    {
        private readonly HttpListener listener = new HttpListener();
        private readonly Func<HttpListenerRequest, string> responderMethod;

        public Windows_HTTP_Server
            (string[] prefixes, Func<HttpListenerRequest, string> method)
        {
            if (!HttpListener.IsSupported) 
                throw new NotSupportedException("Needs Windows XP SP2, Server 2003 or later.");

            if (prefixes == null || prefixes.Length == 0) 
                throw new ArgumentException("prefixes");

            if (method == null) 
                throw new ArgumentException("method");

            foreach (string s in prefixes) 
                listener.Prefixes.Add(s);

            responderMethod = method;

            listener.Start();
        }

        public Windows_HTTP_Server
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
                    while (listener.IsListening)
                    {
                        ThreadPool.QueueUserWorkItem((c) =>
                        {
                            var ctx = c as HttpListenerContext;
                            try
                            {
                                string rstr = responderMethod(ctx.Request);
                                byte[] buf = Encoding.UTF8.GetBytes(rstr);
                                ctx.Response.ContentLength64 = buf.Length;
                                ctx.Response.OutputStream.Write(buf, 0, buf.Length);
                            }
                            catch (Exception e)
                            {
                                Throw_Exceptions.Throw_Exception_Error("Unknown error.", e);
                            }
                            finally
                            {
                                ctx.Response.OutputStream.Close();
                            }
                        }, listener.GetContext());
                    }
                }
                catch (Exception e)
                {
                    Throw_Exceptions.Throw_Exception_Error("Unknown error.", e);
                }
            });
            return true;
        }

        public Boolean Stop()
        {
            try
            {
                listener.Stop();
                listener.Close();
                return true;
            }
            catch (Exception e)
            {
                return Throw_Exceptions.Throw_Exception_Error("", e);
            }
        }
    }
}
