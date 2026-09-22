void Bad(XPathNavigator xPath, string username)
{
    string query = "//users/user[name/text()='" + username + "']";
    // ruleid: xpath-query-with-nonconstant-argument
    string secret = (string)xPath.Evaluate(query);
}

void Good(XPathNavigator xPath)
{
    // ok: xpath-query-with-nonconstant-argument
    string secret = (string)xPath.Evaluate("//users/user[name/text()='admin']");
}
