void Bad(HttpRequest req, HttpResponse resp, string data)
{
    // ruleid: response-write-unencoded
    resp.Write("<br>data = " + data);
}

void Good(HttpResponse resp)
{
    // ok: response-write-unencoded
    resp.Write("<br>static message");
    StringWriter sw = new StringWriter();
    // ok: response-write-unencoded
    sw.Write("not a response object");
}
