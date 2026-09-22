void Bad(string data)
{
    string root = "/home/user/uploads/";
    // ruleid: file-open-with-nonconstant-path
    using (StreamReader sr = new StreamReader(root + data))
    {
        Console.WriteLine(sr.ReadLine());
    }
}

void Good()
{
    // ok: file-open-with-nonconstant-path
    using (StreamReader sr = new StreamReader("/home/user/uploads/readme.txt"))
    {
        Console.WriteLine(sr.ReadLine());
    }
}
