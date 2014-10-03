using System;

namespace secure_sync
{
    class ThrowExceptions
    {
        public static Boolean ThrowExceptionError(String errorMessage, Exception e)
        {
            Console.WriteLine("A fatal error has just occured: \n\t{0}\n\n" +
                              "The program will now terminate. " +
                              "The exception is printed out below:\n\n{1}\n\n",
                              errorMessage, e.Message);
            return false;
        }
    }
}
