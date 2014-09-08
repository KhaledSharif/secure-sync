using System;

namespace SecureSync
{
    class Throw_Exceptions
    {
        public static Boolean Throw_Exception_Error(String error_message, Exception e)
        {
            Console.WriteLine("A fatal error has just occured: \n\t{0}\n\n" +
                              "The program will now terminate. " +
                              "The exception is printed out below:\n\n{1}\n\n",
                              error_message, e.ToString());
            return false;
        }
    }
}
