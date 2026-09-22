void Bad(string data)
{
    string osCommand = "/bin/ls " + data;
    // ruleid: process-start-single-argument
    Process process = Process.Start(osCommand);
}

void Good()
{
    // ok: process-start-single-argument
    Process process = Process.Start("/bin/ls -l");
}
